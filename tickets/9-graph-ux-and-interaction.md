# Decision: Graph UX and Node Interactions

## Context
We have decided on the basic API contract (`/api/graph` and `/api/node/:id`). The frontend will use `react-force-graph` to visualize the derivation tree.

## Problem
The exact UX for exploring nodes and viewing their details needs to be defined. When a user interacts with the graph, what do they see and how do they navigate the data?

## Constraints & Considerations
- **Filtering**: Nix derivation graphs can be massive. We need UX controls (e.g., a toggle) to hide "safe" derivations and only show vulnerable ones and their critical paths.
- **Node Click**: Clicking a node should open a details pane (modal, sidebar, or bottom sheet) that fetches from `/api/node/:id`.
- **Detail Content**: The pane needs to show the list of CVEs, CVSS scores, and mitigation steps (like `nix-versions` links for alternative versions).
- **Performance**: The graph renderer should handle dynamic visibility toggles smoothly without recalculating the entire layout from scratch if possible.

## Output
Implementation or high-fidelity design specifications for the frontend graph controls, node interaction states, and the details UI.

## Resolution
- **Color Mapping:** Nodes will be colored based on their maximum CVSS V3 severity rating:
  - **White**: Safe (no known vulnerabilities).
  - **Gray**: Transitive risk (safe itself, but on a dependency path to a vulnerable node).
  - **Dark yellow**: Low CVSS rating (0.1 - 3.9).
  - **Dark orange**: Medium CVSS rating (4.0 - 6.9).
  - **Dark red**: High CVSS rating (7.0 - 8.9).
  - **Bright red**: Critical CVSS rating (9.0 - 10.0).
- **Filtering UX ("Hide Safe Nodes"):** We will introduce a toggle switch in the UI. When enabled, it filters the graph data to hide nodes that are entirely safe and have no vulnerable dependencies. It retains vulnerable nodes and those providing a critical path to them (nodes marked as Gray/Transitive Risk), allowing users to trace how a vulnerability enters the system.
- **Node Interaction:** Clicking a node will open a sidebar or details pane fetching data from `/api/node/:id`.
- **Details Pane Content:** 
  - Overview of the derivation.
  - List of CVE details and CVSS scores.
  - Mitigation steps.
  - Links to alternative versions of the package using `nix-versions` (e.g., `https://lazamar.co.uk/nix-versions/...`) and a vulnerability count for each version if possible.