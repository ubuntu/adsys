# Mermaid diagrams

Architecture diagrams for ADSys are built using Mermaid.

Each diagram is defined in `docs/diagrams/` using a `.mmd` file.

A custom theme is used that is suitable for viewing in
light or dark mode.

To use the theme in a new diagram, include the following at the top of any
`.mmd` file:

```
%%{init: {"theme": "base", "themeVariables": {
      'background': '#DDC9D4',
      'primaryColor': '#FFF',
      'primaryTextColor': '#E95420',
      'primaryBorderColor': '#7C0000',
      'lineColor': '#E95420',
      'secondaryColor': '#CECAC5'
}}}%%
```
