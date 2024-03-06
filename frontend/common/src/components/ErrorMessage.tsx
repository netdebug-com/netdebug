import React from "react";
import Alert from "@mui/material/Alert";

export const ErrorMessage: React.FC<{ msg: string }> = (props: {
  msg: string;
}) => {
  return <Alert severity="error">{props.msg}</Alert>;
};
