import { FormControlLabel, Switch } from "@mui/material";
import React, { Dispatch, SetStateAction } from "react";

export type SwitchStateUpdateFn = Dispatch<SetStateAction<boolean>>;
export interface SwitchHelperProps {
  text: string;
  state: boolean;
  updateFn: SwitchStateUpdateFn;
}
export const SwitchHelper: React.FC<SwitchHelperProps> = (props) => {
  return (
    <FormControlLabel
      control={<Switch />}
      label={props.text}
      checked={props.state}
      onChange={() => {
        props.updateFn(!props.state);
      }}
    />
  );
};
