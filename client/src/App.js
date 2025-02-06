import React from "react";
import Login from "./components/login";
import Register from "./components/register";

function App() {
  return (
    <div>
      <h1>Authentication System</h1>
      <Login />
      <hr />
      <Register />
    </div>
  );
}

export default App;
