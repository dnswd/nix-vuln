# Codebase Design

This document outlines the architectural design of `nix-vuln`. We adhere strictly to the principles of deep modules, clear seams, and high testability to maintain a robust and maintainable codebase.

## Deep Modules

We design our system using **Deep Modules**, where a simple **Interface** hides a complex **Implementation**. This provides two main benefits:
1.  **Leverage**: Callers can achieve complex outcomes with minimal setup.
2.  **Locality**: Maintainers can reason about and modify complex logic within a bounded context.

### Example: `graph_builder::build_graph`
The `graph_builder::build_graph` module is a primary example of depth in our system. 
- **Interface**: It exposes a tiny interface, accepting only two `HashMap`s (one for parsed derivations, one for CVE data) and a root derivation path.
- **Implementation**: Behind this simple interface, the implementation handles exhaustive graph traversal, dependency deduplication, transitive risk calculation (identifying upstream risks), and CVSS scoring logic.

This depth provides massive leverage to the caller, `App::build_graph`, which only needs to orchestrate the inputs. Furthermore, it ensures high locality for testing: the pure graph computation logic can be tested entirely in memory without requiring complex I/O mock setups.

## Seams and Adapters

A **Seam** is a boundary where an interface lives, allowing us to swap out behavior without changing the calling code. An **Adapter** fills this seam to provide specific functionality. 

### The Database Seam
Vulnerability data retrieval is abstracted behind the `CveDatabase` seam. 
- **Adapter**: In production, we use an embedded `redb` adapter to fulfill this interface, providing fast, low-overhead key-value storage and retrieval for CVE records. 
- This seam allows us to easily inject in-memory adapters during testing or migrate to different storage backends in the future without altering the core risk calculation logic.

### The Nix Store Seam
Parsing derivation files is managed by the `nix_store::parse_derivation` module.
- **Interface**: It exposes the clean `DerivationInfo` interface.
- **Implementation**: It acts as a deep module that completely hides the complexity of raw A-Term byte parsing. 
- This seam separates the messy reality of the filesystem and Nix internals from the clean data structures our application requires.

## Testability

Our design inherently prioritizes testability by strictly separating pure computation from side effects.

By isolating side effects—such as filesystem `.drv` reads at the Nix store seam and key-value reads at the database seam—our core logic remains pure. The `graph_builder` module, for example, relies entirely on standard in-memory data structures passed through its interface. 

Because we rely on well-defined seams rather than deeply coupled implementations, we can test our modules at their seams using simple, predictable adapters. This eliminates the need for complex internal mocking frameworks and ensures our test suite remains fast, reliable, and tightly focused on the actual business logic.
