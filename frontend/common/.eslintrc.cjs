module.exports = {
  root: true,
  env: { browser: true, es2020: true },
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:react-hooks/recommended",
  ],
  ignorePatterns: ["dist", ".eslintrc.cjs"],
  parser: "@typescript-eslint/parser",
  plugins: ["react-refresh"],
  rules: {
    /* TODO: disable this check for now. It wasn't on in 
    electron and it's not really clear how useful it is anyways. 
    */
    /*
    "react-refresh/only-export-components": [
      "warn",
      { allowConstantExport: true },
    ],
    */
  },
};
