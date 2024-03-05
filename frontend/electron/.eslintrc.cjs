module.exports = {
  root: true,
  env: { browser: true, es2020: true, node: true },
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:react-hooks/recommended",
    "plugin:@typescript-eslint/eslint-recommended",
    "plugin:import/electron",
    "plugin:import/typescript",
  ],
  ignorePatterns: ["dist", ".eslintrc.cjs"],
  parser: "@typescript-eslint/parser",
  plugins: ["react-refresh"],
  rules: {
    /* TODO: this rule triggers in a lot of our react code because 
       we mix react components and "regular" functions in the same file.
       Apparently, this rule doesn't like this.
    */
    /*
    "react-refresh/only-export-components": [
      "warn",
      { allowConstantExport: true },
    ],
    */
  },
};
