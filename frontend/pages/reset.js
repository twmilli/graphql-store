import React from "react";
import Reset from "../components/Reset";

const reset = props => {
  return (
    <div>
      <p>Reset Your Password</p>
      <Reset resetToken={props.query.resetToken} />
    </div>
  );
};

export default reset;
