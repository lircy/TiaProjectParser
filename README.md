# Implementing TIA Portal Symbol Variable Tree Parsing with Zero-Dependency C# APIs

> No TIA Portal installation, no PLC connection, no Siemens runtime components — pure managed C# reads `.apXX` project files directly and reconstructs a symbol variable tree that is line-for-line identical to S7 online browsing.
>
> Keywords: TIA Portal, .ap14/.ap17/.ap20, PEData.plf, symbol table, AccessSequence, zero dependency

---

## Table of Contents

1. [Background](#1-background)
2. [Overall Architecture](#2-overall-architecture)
3. [File Format Reverse Engineering: From .apXX to an Object Graph](#3-file-format-reverse-engineering-from-apxx-to-an-object-graph)
4. [The Database Object Model and Dual-Stream Semantics](#4-the-database-object-model-and-dual-stream-semantics)
5. [DB Discovery and Ordering](#5-db-discovery-and-ordering)
6. [Interface Parsing and the Member Tree](#6-interface-parsing-and-the-member-tree)
7. [AccessSequence Construction Rules](#7-accesssequence-construction-rules)
8. [Type System Mapping (Softdatatype)](#8-type-system-mapping-softdatatype)
9. [PLC Tag Tables (I/Q/M/C/T Areas)](#9-plc-tag-tables-iqmct-areas)
10. [Quoting Rules for Dotted Names](#10-quoting-rules-for-dotted-names)
11. [Tree Building and the Offline Browser GUI](#11-tree-building-and-the-offline-browser-gui)
12. [PLC Info Extraction: Aligned with the Online Driver's Four Fields](#12-plc-info-extraction-aligned-with-the-online-drivers-four-fields)
13. [Verification: Dual Ground-Truth Diffing and a 25-Project Matrix](#13-verification-dual-ground-truth-diffing-and-a-25-project-matrix)
14. [Pitfalls Encountered in Practice](#14-pitfalls-encountered-in-practice)
15. [Minimal Runnable Example](#15-minimal-runnable-example)
16. [Conclusion](#16-conclusion)

---

## 1. Background

Industrial HMI scenarios frequently demand one capability: **given a TIA Portal project file and no Siemens software environment whatsoever, know which PLCs the project contains, which DB blocks each PLC has, what each block's interface looks like, and which I/Q/M tags exist**. Typical use cases:

- **Offline browsing**: on site without a TIA Portal license — or without a machine that can run it — but you still need to inspect variable definitions in the project;
- **Data acquisition integration**: the HMI must read/write variables in DB blocks, which requires knowing each variable's **absolute access address** (e.g. the `Velocity` member of the `AxisUM01` struct in `DB4`);
- **Documentation generation, diffing, version archiving**: parse project files into text symbol tables and track engineering changes with git;
- **Cross-checking with the online collection system**: the online driver (S7CommPlus) can browse the PLC's symbol table; the offline side must produce **byte-identical** output for a seamless switchover.

Siemens' official route is TIA Openness (XML export), but it requires a **TIA Portal installation** plus licensing; the AGL/online browsing components require a **PLC connection** or referencing Siemens runtime DLLs. This article describes a different route:

> **Treat the `.apXX` project file as a data file and parse it directly.** An `.apXX` is essentially a ZIP archive containing a self-describing object database. We use a pure managed .NET library (1666 source files, targeting .NET Framework 4.0, C# 7.3, depending only on `System.IO.Compression`) to read it into an object graph, then rebuild on top of it a symbol variable tree that matches S7 online browsing exactly.

Every conclusion in this article has passed dual ground-truth verification: line-by-line diffing against the truth table exported by **online browsing of our own PLC** (192.168.0.250), and diffing against the AGL file-loading component across 25 projects — **zero real gaps**. The article presents the complete decision rules, code skeletons, and a pitfall log.

> Disclaimer: this content is limited to technical research on our own project files and our own devices. The reverse-engineering conclusions are derived from observations of public behavior and self-produced files, and involve no crypto circumvention or license bypass.

---

## 2. Overall Architecture

The system has four layers, bottom-up:

```
┌─────────────────────────────────────────────────────────────┐
│ Delivery  TiaSymbolExport (CLI symbol table)  TiaOfflineBrowser
│           (WinForms offline browser)  PlcInfoExtractor (PLC info)│
├─────────────────────────────────────────────────────────────┤
│ Enumer.   TiaSymbolEnumerator (block discovery / interface walk
│           / tag tables / tree hooks)                        │
│           ISymbolSink / TreeBuildingSink (row output & tree  │
│           building share one traversal)                      │
├─────────────────────────────────────────────────────────────┤
│ Business  TiaProjectExplorer (Facade: Open/OpenLazy/tree walk/
│           search/high-level conversion)  HighLevelObjectConverter
│           (StorageBusinessObject → DataBlock / tag table / …) │
├─────────────────────────────────────────────────────────────┤
│ File      TiaFileProvider (.apXX ZIP / unpacked dir / .plf   │
│           dispatch)  TiaDatabaseFile (PLF binary DB + lazy   │
│           object model)                                      │
└─────────────────────────────────────────────────────────────┘
```

Key design decisions:

1. **Single source of truth.** The symbol enumeration algorithm (`TiaSymbolEnumerator`) exists exactly once: the CLI text export uses it, and the GUI tree building uses it too (via an `ISymbolSink` hook). Row output and tree display can never diverge.
2. **Lazy + explicit-full dual mode.** `OpenLazy` opens without parsing any object; the browse tree parses one level on demand. `ParseAllObjects()` performs an explicit full parse (large projects can take tens of seconds — run it on a background thread).
3. **Fault tolerance everywhere.** Project files are production data; any field can be missing. Every parse path never throws — failures leave fields empty or skip, so the GUI never crashes.
4. **Zero Siemens dependencies.** No Openness, no AGL, no Siemens DLLs. The truth-source tools used for verification exist only in the validation pipeline, never in the runtime path.

---

## 3. File Format Reverse Engineering: From .apXX to an Object Graph

### 3.1 Outer Layer: .apXX Is Just a ZIP

A TIA Portal project file (`.ap14`, `.ap17`, `.ap20` … — the extension digits are the version number) is a standard ZIP archive. After unpacking, the most important entry is:

```
System/PEData.plf          ← main database (object dictionary)
System/PEData-01.plf …     ← additional shards for large projects
```

`TiaFileProvider` dispatches the input: a directory (unpacked project), a single file (`.apXX`/`.zapXX` archive), or a single `.plf` stream all open fine. The classification is straightforward — first probe whether `ZipArchive` can open it, then classify by extension and internal entry names. Core skeleton:

```csharp
public static TiaFileProvider CreateFromSingleFile(string filePath)
{
    var tiaFileProvider = new TiaFileProvider();
    tiaFileProvider._filePath = filePath;
    tiaFileProvider.DetectType();
    return tiaFileProvider;
}

private void DetectType()
{
    _stream = new FileStream(_filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
    bool flag = IsZipArchive(_stream);       // probe: new ZipArchive(...) succeeds?
    _stream.Position = 0L;
    if (flag)
    {
        OpenAsArchive();                     // locate the system/pedata.plf entry as DB root
    }
    else if (Path.GetExtension(_filePath).ToLower() == ".plf")
    {
        TiaFileProviderType = TiaFileProviderType.TiaPLF;
    }
    else
    {
        TiaFileProviderType = TiaFileProviderType.TiaProjectFile; // single file in an unpacked dir
    }
}

public Stream GetDatabaseFileStream(int index)
{
    if (index == 0) return GetStream("System/PEData.plf");
    string file = "System/PEData-" + index.ToString().PadLeft(2, '0') + ".plf";
    return GetStream(file);
}
```

Two engineering details:

- **Shared reads.** All `FileStream`s are opened with `FileShare.ReadWrite` — the project file may be held open by TIA Portal; we only read and never lock.
- **Non-disposing stream wrapper.** `NonDisposeableStream` wraps the underlying shared stream so a caller's `using` cannot prematurely close it.

### 3.2 Inner Layer: the PLF Binary Database

`PEData.plf` is a self-describing binary database: the header records the product version, followed by chunked record sections. The `ProductVersion` parsed from `FileHeader` (e.g. `1400.100.1201.1`) drives all subsequent format dispatch — the `TiaVersion` scale maps one-to-one onto TIA Portal major versions:

| ProductVersion.Major | TIA Version | Common Extension |
|---|---|---|
| 1300 | TIA V13 | .ap13 |
| 1400 | TIA V14 | .ap14 |
| 1500 | TIA V15 | .ap15 |
| 1600 | TIA V16 | .ap16 |
| 1700 | TIA V17 | .ap17 |
| 2000 | TIA V20 | .ap20 |

> Verified in practice: one single parsing codebase opens, parses, and exports V13–V20 projects successfully (see the version matrix in Section 13). V13/V14 container-header XMLs lack the `<ProjectVersion>` element; the project version falls back to the binary file header's `ProductVersion`.

After loading, the database offers two views:

- **`AllStorageObjects`**: the linear list of all storage objects (file order);
- **`StorageObjectDictionary`**: a dictionary keyed by `InstId` (instance ID) — for the same `InstId`, later writes override earlier ones. This is the physical basis of "latest copy wins" (Section 4, dual-stream semantics).

### 3.3 The Object Graph: StorageObject → Business Object

Each `StorageObject` carries:

```csharp
Header.StoreObjectId.InstId      // 64-bit instance ID, unique per object (shared by all versions)
Header.StoreObjectId.RelId       // relation ID (DB blocks: RelId = 0x8A0E0000 | number, see §7)
Header.ObjectStates              // object state flags
```

`StorageBusinessObject` adds on top:

- **`TiaTypeName`**: the fully qualified type name, e.g. `"Siemens.Simatic.Lang.Model.Blocks.DataBlockData"` — the primary handle for reverse engineering, driving all type dispatch;
- **`Children`**: a set of `BaseBusinessObject` child-attribute objects:
  - `BaseExpando`: arbitrary key-value pairs (a `Data` dictionary) — much of the project's miscellaneous information lives here;
  - `BaseRelationList`: a relation table pointing at other objects (`Relations`, each with a `Name` + `StoreObjectId`);
  - `InterfacePartData`: **the interface payload** — `Kind` (e.g. `DBSource`) + `Payload.DataAsString` (XML text). The native carrier of block interfaces and type definitions;
- **`Parent`**: the parent chain (note: the parent chain comes from **relation resolution**, not necessarily the tree-structural parent);
- **`ProjectTreeChildren`**: project tree children (current view).

Relations are the nervous system of the object graph. `GetRelationsWithNameResolved(name)` resolves target objects by relation name; differences between version layouts almost always show up as combinations of "relation name + type name", which is exactly what makes V13–V20 compatibility feasible: **never assume any fixed structure — probe dynamically by type name / relation name, and fall back when not found**.

```csharp
// Top-level facade: open + full parse
using (TiaProjectExplorer explorer = TiaProjectExplorer.Open(path))   // auto ParseAllObjects
{
    // Or lazy: OpenLazy(path), then GetChildren / EnumerateTree on demand
    foreach (StorageBusinessObject obj in explorer.EnumerateTree(explorer.ProjectRootObject, 12))
    {
        Console.WriteLine(obj.TiaTypeName + "  " + obj.Name);
    }
    IHighLevelObject highLevel = explorer.ConvertToHighLevel(obj); // → DataBlock etc.
}
```

---

## 4. The Database Object Model and Dual-Stream Semantics

This is the most counter-intuitive part of the whole reverse-engineering effort, and the easiest to get wrong — hence its own section.

### 4.1 Dual Streams: Download State vs. Editing Index

The AP database simultaneously holds two "streams":

| Stream | Meaning |
|---|---|
| **Stream 0** | The version last **downloaded to the PLC** (its in-project timestamp can be quite old) |
| **Stream 1** | The latest editing **index** thereafter (including changes never downloaded) |

The same `InstId` can appear multiple times in `AllStorageObjects`; `StorageObjectDictionary` overrides on later writes, so **under natural ordering the latest stream wins**.

> **Measured case (FB1DB vs. Static_1)**: in project `测试DB.ap18`, the multi-instance member of `SE_DB` — under stream 0 (download state) the old interface name is `Static_1` (a 5-input version from an earlier FB test); only in the latest stream is it `FB1DB` (the new interface with 2 inputs + ide/STA sections). Pick the wrong stream and the export reads `PLC_2.SE_DB.Static_1[1].ind01` — completely wrong against TIA Portal's current view.

Therefore the default export semantics = **latest stream** (TIA Portal's current view). The online PLC runs the download state, so when diffing against the online ground truth we switch `--gt` mode to stream-0 semantics:

```csharp
/// Stream-0 priority: rewrite the dictionary in reverse so stream 0 (download state)
/// overrides the same InstId; objects that exist only in stream 1 keep their version.
public static void PreferStreamZeroObjects(TiaDatabaseFile db)
{
    for (int i = db.AllStorageObjects.Count - 1; i >= 0; i--)
    {
        db.StorageObjectDictionary[db.AllStorageObjects[i].Header.StoreObjectId.InstId]
            = db.AllStorageObjects[i];
    }
}
```

### 4.2 Historical Copies: the File Is Haunted

TIA Portal **does not physically delete** deleted objects: after a block is deleted and re-created its `InstId` changes, and the old copy lingers in the file; when a tag table is rebuilt, the entire old table remains. Measured examples:

- tiaProject1 (V17): `AllStorageObjects` contains **133 historical `Hymson_PLC` copies**, none of which is in the current project tree;
- `测试DB.ap18`: one tag table lingers as **6189 × 3 copies**; picking an old copy loses the **entire table's tags** (its `TagTableData.Content` relation is missing);
- `dbGen_1024` was deleted and re-created: block number 10 before 2026-08-02, renumbered 66 afterwards — old copies still say 10.

**Conclusion: always trust the "current view", never the raw order or naive dedup of `AllStorageObjects`.** Two authoritative paths:

1. **Tree walk** (`EnumerateTree`, pre-order along `ProjectTreeChildrenSorted`) — the project tree's current view, which naturally drops historical copies. PLC discovery and node browsing use this.
2. **Latest per InstId + business-key fallback dedup** — symbol export uses this (it must scan all blocks/tags and tolerate tree anomalies): take the last record per InstId, then deduplicate again by `(PLC, block number)` / `(PLC, area, LID)` keeping the last occurrence.

---

## 5. DB Discovery and Ordering

### 5.1 Type Filtering

DB blocks have 4 possible `TiaTypeName` values (two namespaces × plain/technological):

```csharp
private static readonly HashSet<string> DbTypeNames = new HashSet<string>(StringComparer.Ordinal)
{
    "Siemens.Simatic.Lang.Model.Blocks.DataBlockData",
    "Siemens.Simatic.PlcLanguages.Model.DataBlockData",
    "Siemens.Simatic.Lang.Model.Blocks.TechnologicalDataBlockData",
    "Siemens.Simatic.PlcLanguages.Model.TechnologicalDataBlockData"
};
```

### 5.2 Discovery, Dedup, Ordering (matching the online object-table order)

This step determines whether the export order can diff against online browsing at all; every rule was reverse-derived from diffs:

```csharp
public List<DataBlockInfo> FindDataBlocks(TiaProjectExplorer explorer, int? onlyDb)
{
    // ① One per InstId: default (latest stream) takes the newest copy; --gt takes stream 0
    Dictionary<long, StorageBusinessObject> perInstId = new Dictionary<long, StorageBusinessObject>();
    foreach (StorageObject so in db.AllStorageObjects)
    {
        StorageBusinessObject sb = so as StorageBusinessObject;
        if (sb == null || !DbTypeNames.Contains(sb.TiaTypeName)) continue;
        long instId = sb.Header.StoreObjectId.InstId;
        if (LatestStream || !perInstId.ContainsKey(instId))
            perInstId[instId] = sb;
    }

    // ② Convert to high-level DataBlock; resolve owning PLC (walk Parent chain up to S7ControllerTargetData)
    foreach (KeyValuePair<long, StorageBusinessObject> kv in perInstId)
    {
        DataBlock dataBlock = explorer.ConvertToHighLevel(kv.Value) as DataBlock;
        if (dataBlock == null) continue;
        DataBlockInfo info = new DataBlockInfo { InstId = ..., Number = dataBlock.Number,
                                                 Name = dataBlock.Name, Block = dataBlock, Sb = kv.Value };
        ResolvePlc(kv.Value, out info.PlcInstId, out info.PlcName);   // group by PLC in multi-PLC projects
        result.Add(info);
    }

    // ③ Multiple copies per (PLC, number) → keep the last occurrence (latest stream = current view)
    Dictionary<long, Dictionary<int, DataBlockInfo>> byPlcNumber = ...;   // dedup per PLC group

    // ④ Ordering: PLCs by InstId ascending; within each PLC the main body by InstId
    //    ascending (first-download order = online GetObjects enumeration order),
    //    tail blocks by number ascending
    long fobOwner = FindFobGuidOwnerInstId(db);
    foreach (long plcKey in plcKeys)
    {
        foreach (DataBlockInfo info in byPlcNumber[plcKey].Values)
        {
            bool inTail = info.Block.InstanceOfName == "TO_PositioningAxis"
                       || info.Block.InstanceOfName == "F_CTRL_1"
                       || info.InstId == fobOwner;
            (inTail ? tail : main).Add(info);
        }
        main.Sort((a, b) => a.InstId.CompareTo(b.InstId));
        tail.Sort((a, b) => a.Number.CompareTo(b.Number));
        main.AddRange(tail);
    }
    return result;
}
```

Three hard-won specials worth calling out:

- **Tail-block determination**: axis technological objects (`InstanceOfName == "TO_PositioningAxis"`), `F_CTRL_1` (block 30000), and block 30043 (which carries the FOB interface guid) sort at the end of the online object table, by block number ascending. Blocks 30043 and 30044 are both SharedDB — the **only distinguishing signal** is that 30043's `DBSource` payload (`<Root ...>` XML) carries the FOB (fail-safe block) interface guid `eadca34c-3962-43cd-a61c-e17423f8de4a`, unique across the whole file.
- **F_SystemInfo_DB (30001)**: the online PLC content is the safety compiler's **latest product** (containing the signature structure); the file's stream-0 "download state" record is stale. Solution: find the `InterfaceVersionRootData` whose `DBSource` payload contains a `HardwareSignature` member and whose `UsedByBlock` relation points at the block (a stream-1 product), and override the interface parsing with its version root.
- **Multi-PLC projects**: `测试DB.ap18` has same-numbered blocks in `PLC_2`/`PLC_OPCUA`; dedup and ordering must both happen inside the PLC group. Row names always carry the PLC-name prefix (single-PLC projects too — uniform output format).

---

## 6. Interface Parsing and the Member Tree

### 6.1 The Physical Form of an Interface

A block's interface is not stored as an intuitive "member list"; it is an `InterfacePartData` (`Kind = DBSource`) hanging off `InterfaceVersionRootData`, whose payload is **XML text describing the member structure**. The library's `InterfaceParserV14` parses it into a strongly typed model:

```csharp
CodeBlockInterface
└── MemberValues : List<MemberInstance>
    ├── Member : Member        // Name / LID / RID / Section / BaseTiaDataType /
    │                          // ParsedDataType (array dims, original type name) / IsArray /
    │                          // ArrayIndexes (element subscripts) / IsAtChild (AT view)
    └── Children : List<MemberInstance>   // child members (struct / array elements)
```

Each `Member` carries an **LID** (logical ID, Local ID) — the source of the hexadecimal segments in the access sequence.

### 6.2 Section Flattening Rules

Block interface members are stored in sections: `Input / Output / InOut / Static / Temp / Constant / Base`. The online browser's flat list treats them differently; `FlattenSections` reproduces this exactly:

```csharp
/// Temp/Constant are skipped (not present online); Base is kept member-level;
/// other sections merge their children into the current level.
private List<MemberInstance> FlattenSections(List<MemberInstance> children, ...)
{
    foreach (MemberInstance mi in children)
    {
        Section section = mi.Member as Section;
        if (section == null) { flat.Add(mi); continue; }
        if (section.Section == SectionType.Temp || section.Section == SectionType.Constant) continue;
        if (section.Section == SectionType.Base) { flat.Add(mi); continue; }
        flat.AddRange(FlattenSections(SafeChildren(mi), ...));   // Input/Output/… merge transparently
    }
    return flat;
}
```

After flattening, sort **by LID ascending** — the physical allocation order online.

### 6.3 Recursive Member Walk

`WalkMemberInstance` is the core recursion; each member shape has its own branch:

```csharp
private void WalkMemberInstance(MemberInstance mi, string namePrefix, string accessPrefix, ...)
{
    Member member = mi.Member;
    if (member is Section)   // only Base reaches here: empty name component + own LID segment
    {
        string baseName   = namePrefix + ".";                        // name gains ".."
        string baseAccess = accessPrefix + "." + mi.LID.ToString("X");
        WalkLevel(SafeChildren(mi), baseName, baseAccess, ...);
        return;
    }
    if (member.IsAtChild && !LatestStream) return;    // AT-view members: not shown in online browse
    if (!inBase && IsTechnologyObject(member)) return; // tech objects (RID 0x0204 family) expand
                                                      // only at the top level of technological DBs

    if (mi.IsArray && mi.ArrayIndexes == null)   // array parent: no row; export elements one by one
    {
        TreeSink?.OnContainer(...);               // GUI: attach the array container node
        foreach (MemberInstance element in mi.Children)
            WalkArrayElement(element, namePrefix, accessPrefix + "." + mi.LID.ToString("X"), ...);
        return;
    }

    string name   = namePrefix   + "." + mi.Name;
    string access = accessPrefix + "." + mi.LID.ToString("X");

    if (LatestStream && IsDbReferenceMember(member) && member.Section == SectionType.InOut)
    {
        // InOut DB reference member (RID 0x02080264): passed by reference in the compile
        // product — AGL file loading emits a flat Pointer row, does not expand the
        // referenced structure's children
        EmitLeaf(name, access, 20 /* Pointer */, ...);
        return;
    }

    List<MemberInstance> kids = SafeChildren(mi);
    if (kids != null && kids.Count > 0)   // struct: no row; children recurse sorted at this level
    {
        if (LatestStream && (TypeName(member) == "DTL" || TypeName(member) == "LDT"))
            EmitLeaf(name, access, TypeName(member) == "DTL" ? 67u : 66u, ...); // DTL/LDT flat rows
        WalkLevel(kids, name, access, ...);
    }
    else                                  // leaf
    {
        uint type = LeafType(member);
        EmitLeaf(name, access, type, ...);
    }
}
```

Array elements go through `WalkArrayElement`: the name comes straight from `element.Name` (`MemberInstance.Name` already includes `[subscript…]`); the access sequence uses the **linearized element LID**; a **struct array element** appends the constant `.1` after the element LID before recursing (matching the online access sequence — see 7.4).

---

## 7. AccessSequence Construction Rules

The access sequence is the core of online-browse diffing and the finest-grained rule set in the whole project. Export row format:

```
Name \t AccessSequence \t Softdatatype
```

Example (member `Velocity` of struct `AxisUM01` in DB4, reached via the Base section):

```
AxisUM01..Velocity	8A0E0004.8.9	Real
```

Segment by segment:

### 7.1 DB Block Segment: RelId

```
RelId = 0x8A0E0000 | block number        (uppercase hex)
```

`8A0E0004` is block 4.

### 7.2 Member Segments: the LID Chain

Each deeper level under the block appends `.` + the member LID in hex: `8A0E0004.8.9` reads "DB4 → Base section (LID 8) → Velocity (LID 9)".

### 7.3 The Base Section's Empty Name Component

The Base section (the inherited base-type part of a UDT/FB) appears in the name as an **empty segment** — the two consecutive dots in `AxisUM01..Velocity`. That is exactly why the Base branch adds `"."` to the name.

### 7.4 Arrays

- **Element LID**: 1-D arrays = linearized 0-based index; **multi-dimensional arrays are not simply linearized** — the online side computes strides with "last-dimension byte alignment":

```csharp
/// lid = Σ (idx_k - start_k) · S_k
/// S_last = ceil(n_last · bitSize / 8) · 8 / bitSize   (rows are byte-aligned)
/// higher dimensions use the raw element count as stride.
private static uint ArrayElementLid(MemberInstance element)
{
    if (element.ArrayIndexes != null && element.ArrayIndexes.Length >= 2)
    {
        ParsedDataType parsed = element.Member.ParsedDataType;
        if (parsed != null && parsed.IsArray && parsed.ParsedDimensions != null)
        {
            int m = parsed.ParsedDimensions.Count;
            if (m == element.ArrayIndexes.Length && m >= 2)
            {
                int bitSize = ElementBitSize(parsed.BaseTiaDataType);
                if (bitSize > 0)
                {
                    ulong lid = 0UL;
                    for (int k = 0; k < m; k++)
                    {
                        ulong stride = 1UL;
                        for (int j = k + 1; j < m; j++)
                        {
                            int countJ = endJ - startJ + 1;
                            if (j == m - 1)
                                stride *= (ulong)(((countJ * bitSize + 7) / 8) * 8 / bitSize);
                            else
                                stride *= (ulong)countJ;
                        }
                        lid += (ulong)(element.ArrayIndexes[k] - start) * stride;
                    }
                    return (uint)lid;
                }
            }
        }
    }
    return element.LID;
}
```

Ground-truth verification: `IOConfig.X[0..10,0..24,0..16]` (BBOOL, bit width 1) → last-dim stride = `ceil(17·1/8)·8/1 = 24`, higher-dim stride = 25 → `S2=24, S1=600`; `ProjectName[0..9,0..9]` (UInt) → linearized 0..99 (10 × 16-bit elements in the last dim happen to be byte-aligned, so both algorithms agree).

- **Struct array elements**: after the element LID, append the constant `.1`, then descend into the element type's members (e.g. `8A0E0005.A.3.1.7`).

### 7.5 Tag Segment: Area RelId

The tag access sequence starts with the area's RelId (Section 9): `50.xxx` (I area), `51.xxx` (Q area), `52.xxx` (M area).

---

## 8. Type System Mapping (Softdatatype)

`Softdatatype` is the S7 type enumeration (0–256), kept fully consistent with the online driver's `Softdatatype.Types` table. Excerpt:

| Value | Name | Value | Name | Value | Name |
|---|---|---|---|---|---|
| 1 | Bool | 19 | String | 40 | BBOOL |
| 2 | Byte | 20 | Pointer | 48 | LReal |
| 4 | Word | 22 | Any | 63 | Variant |
| 6 | DWord | 31 | IEC_TIMER | 66 | LDT |
| 7 | DInt | 36 | Block_OB | 67 | DTL |
| 8 | Real | 37 | Block_UDT | 208 | DB_ANY |

### 8.1 Emission Rules

Only types supported by online browsing produce symbol rows (the `SupportedTypes` whitelist); **unsupported types produce no row themselves, but their children still recurse** — which is why container types like `Struct`/`Array`/`IEC_TIMER` "not appearing" is normal.

### 8.2 Optimized Blocks: Bool → BBOOL

```csharp
private void EmitLeaf(string name, string access, uint type, ...)
{
    if (type == 1U && optimized && !insideIec)
        type = 40U;   // online browse: Bool in an optimized block → BBOOL
    if (type == 0 || !SupportedTypes.Contains(type))
    {
        if (type != 63U || !LatestStream) return;   // Variant only emits a flat row under AGL semantics
    }
    rows.Add(name + "\t" + access + "\t" + typeName);
    TreeSink?.Emit(treeName ?? name, access, type, typeName, depth);
}
```

The `insideIec` flag comes from `IsIecFamily`: Bools inside the IEC timer/counter family (`TON_TIME`/`IEC_TIMER`/`CTU`… — determined by type name, since `BaseTiaDataType` can't distinguish them, all being `Block_UDT`) and inside the system data types `RDREC`/`WRREC` (SFB52/53) **stay Bool online, not upgraded even in optimized blocks**. Note the reverse special case: fail-safe timers like F-TON are **user FBs** in the same RID 0x0203 family, but their internal Bools are BBOOL online — so judging by the whole RID family is wrong; the type name must be used.

### 8.3 Special Flat Rows (latest-stream / AGL semantics only)

- **DB reference members** (RID `0x02080264`, InOut section): e.g. `MB_DB` of `Modbus_Comm_Load_DB` — passed by reference in the compile product → a flat `Pointer` row, not expanded (the Static-section member of the same name is inlined/expanded instead).
- **DTL/LDT**: besides expanding the fields, also emit a flat row for the member itself (`timeMeasure.start` etc.).
- **Variant**: not produced by online browse; AGL file loading emits a flat row (`RDREC.RECORD`, `BUFFER`, `CONNECT` etc.).

---

## 9. PLC Tag Tables (I/Q/M/C/T Areas)

Tag tables have a completely different physical shape from DBs: `EAMTZTagTableData` (tag table) carries `EAMTZTagData` (each tag) via relations, and each tag carries a `TagAddress` child object (`RuntimeIdentifier` = area enum, `LocalIdentifier` = LID):

```
Area enum: Input=80, Output=81, Flags=82, Counters=83, Timers=84
Area RelId = (int)area - 30      → I=50, Q=51, M=52, C=53, T=54
```

```csharp
foreach (StorageBusinessObject rel in table.GetAllRelationsResolved())
{
    if (rel == null || rel.TiaTypeName != "Siemens.Automation.DomainModel.EAMTZTagData") continue;
    TagAddress addr = rel.GetChild<TagAddress>();
    if (addr == null) continue;
    Area area = (Area)addr.RuntimeIdentifier;
    if (area != Area.Input && area != Area.Output && area != Area.Flags
        && area != Area.Counters && area != Area.Timers) continue;
    byArea[(int)area - 80].Add(new TagEntry { Rel = rel, Area = area,
                                              LId = (int)addr.LocalIdentifier, PlcName = plcName });
}
// Per (PLC, area): dedup by LID (stale-table leftovers → keep last) + LID ascending;
// area order I→Q→M→C→T
```

A single tag emits in one of two ways:

1. **Flat tag**: `dtRef.Name` parses directly to a base type (`ParseBaseType`, auto-stripping the `[N]` length suffix such as `String[254]`) → one row for itself (`optimized=false`, Bool not upgraded).
2. **Structured tag**: via the `DataTypeRef` relation, take the UDT/system-data-type definition, go through the library's standard conversion path (`ConvertToHighLevel` → `BaseBlock.Interface`) to get the UDT interface, then reuse the very same `WalkLevel` recursion to export members (optimization rules identical to blocks).

Two engineering details:

- **UDT conversion cache**: convert each UDT exactly once. The library converter's repeated `Convert` of the same object triggers a `StackOverflow` in the parser's second parse (conversion-option value equality fails, so the wrapper cache never hits) — you must cache interfaces by `InstId` yourself.
- **Naming**: the `IArea`/`QArea`/`MArea`/`CArea`/`TArea` prefixes are **online-browse naming**, unrelated to the in-project tag table name (often the Chinese "默认变量表"); multi-PLC projects stack the PLC name prefix on top: `PLC_2.MArea.StartPB`.

---

## 10. Quoting Rules for Dotted Names

Symbol names **containing dots** are common: `I0.0`, `Clock_2.5Hz`, `DB3.DBW0`. In a tree path that layers on `.`, such names must be treated as **one inseparable segment**. The rule matches the access-sequence escaping convention:

> Only segments consisting entirely of `[0-9A-Za-z_]` stay unquoted; everything else (containing `.`, `-`, Chinese characters, leading digits, etc.) is wrapped in double quotes.

```csharp
private static string TiaTreeSegment(string seg)
{
    if (seg.Length > 0)
    {
        bool plain = true;
        foreach (char c in seg)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z') || c == '_')) { plain = false; break; }
        }
        if (plain) return seg;
    }
    return '"' + seg + '"';
}
```

So the tree-path segment of `Clock_2.5Hz` is written `"Clock_2.5Hz"`, and when splitting paths **dots inside quotes are not separators**:

```csharp
private static List<string> SplitQuotedPath(string path)
{
    bool inQuote = false;
    foreach (char c in path)
    {
        if (c == '"') { inQuote = !inQuote; continue; }
        if (c == '.' && !inQuote) { segments.Add(cur); cur.Clear(); continue; }
        cur.Append(c);
    }
    segments.Add(cur.ToString());
    return segments;
}
```

**Note: row output (the Name column) uses no quotes** — quotes exist only for tree-path segmentation; the two never affect each other.

---

## 11. Tree Building and the Offline Browser GUI

### 11.1 Row Output and Tree Building Share One Traversal

The enumerator's only hook point is optional:

```csharp
public interface ISymbolSink
{
    void Emit(string name, string access, uint type, string typeName, int depth);
    void OnContainer(string name, string access, int depth, bool isArrayParent);
}
```

On the CLI path `TreeSink == null` and everything is a no-op — row output is **byte-identical** to before the tree hook existed (the refactoring gate: `cmp` must pass before the change is accepted). When the GUI sets a `TreeBuildingSink`, every leaf row and array-parent container fires one callback.

### 11.2 TreeBuildingSink: Building by Absolute Path

No depth-based parent stack (block paths and tag paths both start at depth 0; stack-based attachment mis-hangs when both entry points coexist) — the tree is built **from the name path itself**:

- The name is split on quote-aware `.`; missing intermediate segments are auto-created (struct containers are created by their child rows);
- Empty segments (the Base section's `..`) display as `Base`;
- Array element segments (`name[subscript…]`) attach automatically under the array parent container created earlier by `OnContainer` (the `IsArrayParent` node);
- The block-member prefix (`PLC.block.`) is stripped from under the root via `prefixToStrip` — the block node already exists in the GUI tree.

### 11.3 TiaOfflineBrowser

A WinForms (net472) offline browser, laid out like the online browser's tree + data pane + status bar:

- **Tree**: root = project (name + version) → one node per PLC → that PLC's DB blocks + 5 area nodes (Inputs/Outputs/Merker/S7Timers/S7Counters); `TreeNode.Tag` holds the payload (InstId/RelId/access sequence);
- **Lazy loading**: opens instantly (`OpenLazy`); expanding a block/area node parses on a background `Task` and mounts the whole member tree at once; the status bar shows `parsing...`;
- **Selecting a leaf** → symbol name (rebuilt via `escapeTiaString`) + symbolic address (access sequence) + type name; selecting a PLC node → the status bar shows the four PLC info fields (Section 12);
- **Headless verification**: `--smoke` mode DFS-walks all leaves and writes `smoke_report.txt` for CI.

Smoke report fragment (ValveCtr.ap14, a V14 project):

```
# Project: ValveCtr  Version: 1400.100.1201.1
# PLCs: 1
PLC PLC_1 (0x56F) Type=CPU 1214C DC/DC/DC MLFB=6ES7 214-1AG40-0XB0 Fw=V4.2 Family=S7-1200
  Net IP=192.168.0.1 Mask=255.255.255.0 Router=192.168.0.1 MAC=0000010600080000 PN=plc_1
# Blocks: 19
DB15 Modbus_Master_DB nodes=3055 leaves=3022
...
# Tags tree: nodes=20 leaves=17
# Blocks total: nodes=15924 leaves=15715
SMOKE-OK
```

---

## 12. PLC Info Extraction: Aligned with the Online Driver's Four Fields

The online driver (SiemensCommDriver) exposes four `S7PlcInfo` fields: order number `S7PlcMLFB`, family `S7PlcFamily`, firmware `S7PlcFirmware`, type name `S7PlcTypeName` — obtained via AGL's `Symbolic_GetS7PlcFamily/Firmware/MLFB/TypeName`. The offline side extracts the same four fields from the project file (`PlcInfoExtractor`):

### 12.1 Locating the PLC Objects

Type name `"Siemens.Simatic.HwConfiguration.Model.S7ControllerTargetData"` (one per PLC). The **authoritative path is the project tree walk** (`EnumerateTree` pre-order collection + dedup by InstId) — see the historical-copy trap in 4.2; when the tree is unavailable, fall back to `AllStorageObjects` taking the last record per InstId.

### 12.2 The Four-Field Resolution Chain (never throws, cascading fallbacks)

```csharp
// ① Device: S7ControllerTargetData.Parent == DeviceData (measured: 'S7-1200 station_1')
//    fallback: CoreObject.Target / BaseDeviceItemData.Parent relations (different version layouts)
// ② CPU device item: the target IS the CPU device item; its child DeviceItemData has the
//    authoritative values
DeviceItemData di = target.GetChild<DeviceItemData>();
rec.MLFB     = di.OrderNumber;        // e.g. 6ES7 517-3FP00-0AB0
rec.Firmware = di.FwVersion;          // e.g. V2.8
rec.TypeName = di.InvariantTypeName;  // e.g. CPU 1517F-3 PN/DP
//    all-empty fallback: CPU item in target/device DeviceItems (old layout),
//    then DeviceData.InvariantTypeName
// ③ Family: device CoreAttributes.Subtype prefix → CPU item subtype prefix
//    → TypeName contents → "UNDEFINED"
//    display format matches online S7PlcFamily.ToString().Replace("_","-")
```

| Subtype Prefix | Family |
|---|---|
| `S71500…` | S7-1500 |
| `S71200…` | S7-1200 |
| `S7300…` | S7-300 |
| `S7400…` | S7-400 |

### 12.3 Network Information

The target's `DeviceItems` relation flattens out the interface items; filter by the six vendor interface subtypes (`S71500.CPU.Interface.IE`, `S71200.CPU.IeInterface`, `PC.CPU.Interface.IE.Plus`, `HMI.Interface`, `S71500.CPU.Interface.DP`, `HMI.CP.PB`), then `NetworkInformationConverter.ParseNetwork` each for IP/mask/router/MAC/PN. When the interface item itself carries no `NodeIPAddress` payload (measured: peds only have `Pn*` flags), the IP lives on the related `NodeData.DeviceItemNodes`.

Measured samples: tiaProject1 → `Fw=V2.8 / 6ES7 517-3FP00-0AB0 / CPU 1517F-3 PN/DP`; tiaProject27 → `Fw=V4.7 / 6ES7 212-1AE40-0XB0 / CPU 1212C DC/DC/DC`. Multi-PLC projects are first-class: `ExtractAll` returns all records (InstId ascending), and the GUI status bar switches with the selected PLC.

---

## 13. Verification: Dual Ground-Truth Diffing and a 25-Project Matrix

"Does it parse correctly" cannot be answered by self-consistency; this project cross-validates against **two independent truth chains**:

### 13.1 Truth Chain A: Online Browsing (GT)

The S7CommPlus online browsing component connects to the user's own PLC (192.168.0.250) and exports `plc_ground_truth.txt`. The offline export switches to `--gt` mode (stream-0 download semantics) and diffs line by line:

- **tiaProject1 (a V17 project with 8 PLCs)**: GT-only = 0 (present online but missing offline: zero); OURS-only = 8217 (stale blocks `8A0E0064/012C/0190/03F2/03FC/0406/0410/041A` across the 8 PLCs — the PLC runs old files; these blocks are **not fixable offline**, a known difference); all 8402 diff lines explained.

### 13.2 Truth Chain B: AGL File Loading

AGL is Siemens' official file-loading component (used only as a reference in our validation environment — never in the runtime path). The diff script normalizes both sides' naming (AGL unquote, `PLC_x.Blocks.`→`PLC_x.`, tag table name → area name), diffing blocks and tags separately:

| Project | Size | Our rows (blocks+tags) | AGL diff |
|---|---|---|---|
| exp2 (Test1.ap17) | 717 objects | 322 (316+6) | 0/0 |
| exp3 (Test2.ap17) | 1212 objects | 12014 (12012+2) | 0/0 |
| exp4 (20190425.ap15) | 2919 objects | 4075 (3724+351) | 0/0 |
| exp5 (测试DB.ap18) | 3764 objects | 38488 (38448+40) | 0/0 |
| exp6 (ValveCtr.ap14) | 1914 objects | **15732 (15715+17)** | 0/0 |

- **Version matrix (tiaProject7–15, V13×2 / V14×2 / V15×2 / V20×3)**: all open + parse + export successfully, AGL diff 0/0. **Including V20** — even the 2017-era AGL reference component loads ap20, and so does our parser.
- **Full 25-project matrix**: zero real gaps. The AGL-only misses are 100% `S7_Pointer` leaves (a known behavior difference of AGL file loading); p18's CC1 safety subsystem is under-read by AGL — our export is more complete.
- **V19 special run**: all 25 DB names/numbers correct (the offset of -1 is correct behavior for optimized blocks, not a defect).

### 13.3 Regression Gates (run on every change)

```
dotnet msbuild sln -t:Rebuild          → 0 errors
VS2017 MSBuild sln -t:Rebuild          → 0 errors
TiaSymbolExport ValveCtr.ap14          → 15736 lines, byte-identical to baseline (cmp)
TiaOfflineBrowser --smoke ValveCtr.ap14 → SMOKE-OK (15715+17=15732)
```

The byte-level `cmp` is the hard gate for any move/refactor — a refactoring "that looks equivalent" only passes when the export result is **byte-identical** to the baseline.

---

## 14. Pitfalls Encountered in Practice

Ranked by cost:

1. **Wrong stream chosen** (4.1): the default taking stream 0 produced the stale `Static_1` name export. → Default to latest stream; `--gt` explicitly switches to stream-0 semantics.
2. **Historical copies** (4.2): 133 ghost PLCs, 6189×3 tag-table copies, renumbered dbGen_1024. → Trust only the current view; after "latest per InstId", dedup again on business keys.
3. **Old copies with missing interface relations**: taking a stale tag-table copy loses the **entire table's tags** (missing `Content` relation) — the symptom is "tags mysteriously missing", not an error.
4. **Multi-dimensional array element LID**: linearization is entirely wrong when the last dimension isn't byte-aligned (BBOOL arrays). → Stride for the last dim = `ceil(n·bits/8)·8/bits`, reverse-derived from ground truth.
5. **The `.1` suffix on struct array elements**: the online access sequence appends a fixed `.1` after the element LID — missing it produces a wall of diffs.
6. **The Bool→BBOOL exception inside optimized blocks**: IEC timer/counter internals don't upgrade; but F-TON etc. (user FBs in the same RID 0x0203 family) do — judging by RID family is wrong; use the type name.
7. **UDT re-conversion StackOverflow**: the converter cache-miss path; build your own InstId cache.
8. **GBK console mojibake**: on Chinese Windows stdout is GBK — always verify via **output files**, never the console.
9. **V13/V14 lack `<ProjectVersion>`**: fall back to the binary file header's `ProductVersion` (V13=1300.109.701.1, V14=1400.0.3101.1).
10. **Blocks 30001/30043**: F_SystemInfo_DB needs the stream-1 version root (containing HardwareSignature); 30043 vs 30044 are distinguishable only by the FOB guid in the DBSource payload.
11. **Dead-field lesson from decompiled-code maintenance**: CS0169 (never used) is safe to remove; CS0414 (written, never read) is removable when writes are pure; **CS0649 (read, never written) must never be removed** — the code reads it (reading the default value), the reads often live in *other classes*, and scanning for references inside the declaring class alone misses them.

---

## 15. Minimal Runnable Example

```csharp
using System;
using System.Collections.Generic;
using TiaFileFormat;
using TiaFileFormat.Wrappers.CodeBlocks.Symbols;
using TiaFileFormat.Wrappers.Controller;

class Program
{
    static int Main(string[] args)
    {
        using (TiaProjectExplorer explorer = TiaProjectExplorer.OpenLazy(args[0]))
        {
            Console.WriteLine("Project: " + explorer.ProjectName + "  Version: " + explorer.ProjectVersion);
            explorer.ParseAllObjects();          // full parse (background thread for big projects)

            // ① DB block symbol table
            TiaSymbolEnumerator en = new TiaSymbolEnumerator();
            List<string> rows = new List<string>();
            foreach (TiaSymbolEnumerator.DataBlockInfo block in en.FindDataBlocks(explorer, null))
                en.ExportBlock(block, rows, null);

            // ② I/Q/M/C/T tag tables
            en.ExportTagTables(explorer, rows, null);

            foreach (string row in rows)
                Console.WriteLine(row);          // Name \t AccessSequence \t Softdatatype

            // ③ PLC info (aligned with the online S7PlcInfo four fields)
            foreach (PlcInfoExtractor.PlcInfoRecord rec in PlcInfoExtractor.ExtractAll(explorer))
            {
                Console.WriteLine(rec.Name + " | " + rec.MLFB + " | " + rec.Family
                                  + " | " + rec.Firmware + " | " + rec.TypeName);
                foreach (string net in rec.Networks)
                    Console.WriteLine("  " + net);
            }
        }
        return 0;
    }
}
```

Sample output:

```
Project: ValveCtr  Version: 1400.100.1201.1
PLC_1.Modbus_Comm_Load_DB.MB_DB	8A0E000A.14	Pointer
PLC_1.Modbus_Master_DB.MB_DB.S_PORT	8A0E000F.17.9	Word
PLC_1.MArea.System_Byte	52.9	Byte
PLC_1.MArea.FirstScan	52.A	Bool
PLC_1 | 6ES7 214-1AG40-0XB0 | S7-1200 | V4.2 | CPU 1214C DC/DC/DC
  IP=192.168.0.1 Mask=255.255.255.0 Router=192.168.0.1 MAC=0000010600080000 PN=plc_1
```

---

## 16. Conclusion

The essence of this approach: **treat the TIA Portal project file as a self-describing database**, and precisely reproduce the online browsing symbol semantics on top of its object graph. The key judgments in retrospect:

- **No Siemens runtime dependencies**: `.apXX` = ZIP + binary object store, readable in pure managed code; V13–V20 compatible.
- **The only standard for correctness is ground-truth diffing**: two independent truth chains (online browse GT and AGL file loading), a 25-project matrix with zero real gaps, and byte-level `cmp` as the hard gate for every refactor.
- **The hard part is not parsing the format — it's the semantics**: dual streams, historical copies, array-LID byte alignment, the Base-section empty segment, the `.1` suffix, the Bool→BBOOL exception families — every single one is a rule extracted from diffing.
- **Architectural patterns worth reusing**: dynamic probing by type name / relation name with cascading fallbacks (the key to version compatibility); a single enumeration core with an optional tree hook (row output and GUI share the source of truth); fault tolerance end to end (production data is not guaranteed to be complete).

Final deliverables: a 1666-file zero-dependency parsing library, a symbol-table CLI exporter (zero gaps on a 15732-row project), an offline browser GUI, and a CI-ready regression gate set.

**Repository and further details**: the implementation behind this article lives in three projects — `TiaFileFormat` (library), `TiaSymbolExport` (CLI), `TiaOfflineBrowser` (GUI). Every rule in this article has a supporting ground-truth case; probe modes (`--probe`/`--tagprobe`/`--plc`) dump the evidence behind each decision.

---

*All ground-truth data in this article comes from measurements on our own projects and our own devices; `plc_ground_truth.txt` was generated by the user's online browse of their own PLC (192.168.0.250).*
