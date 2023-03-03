import React, { useState } from "react";
import "./App.css";
import Axios from "axios";
const { REACT_APP_BACK_URL } = process.env;

function App() {
  const [registerUsername, setRegisterUsername] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [data, setData] = useState(null);

  const authGoogle = () => {
    window.open(`${REACT_APP_BACK_URL}/auth/google`, "_self");
  };

  const register = () => {
    Axios({
      method: "POST",
      data: {
        username: registerUsername,
        password: registerPassword,
      },
      withCredentials: true,
      url: `${REACT_APP_BACK_URL}/register`,
    }).then((res) => console.log(res));
  };
  const login = () => {
    Axios({
      method: "POST",
      data: {
        username: loginUsername,
        password: loginPassword,
      },
      withCredentials: true,
      url: `${REACT_APP_BACK_URL}/login`,
    }).then((res) => console.log(res));
  };
  const getUser = () => {
    Axios({
      method: "GET",
      withCredentials: true,
      url: `${REACT_APP_BACK_URL}/user`,
    }).then((res) => {
      setData(res.data);
      console.log(res.data);
    });
  };

  const logout = () => {
    Axios({
      method: "POST",
      withCredentials: true,
      url: `${REACT_APP_BACK_URL}/logout`,
    }).then((res) => {
      console.log("logout successfully");
    });
  };
  return (
    <div className="App">
      <div>
        <h1>Register</h1>
        <input
          placeholder="username"
          onChange={(e) => setRegisterUsername(e.target.value)}
        />
        <input
          placeholder="password"
          onChange={(e) => setRegisterPassword(e.target.value)}
        />
        <button onClick={register}>Submit</button>
      </div>
      <div>
        <h1>Login</h1>
        <input
          placeholder="username"
          onChange={(e) => setLoginUsername(e.target.value)}
        />
        <input
          placeholder="password"
          onChange={(e) => setLoginPassword(e.target.value)}
        />
        <button onClick={login}>Submit</button>
      </div>
      or
      <button onClick={authGoogle}>Google</button>
      <div>
        <h1>Get User</h1>
        <button onClick={getUser}>Submit</button>
        {data ? (
          <>
            <h1>Welcome Back {data.username ? data.username : data.name}</h1>
            <button onClick={logout}>Logout</button>
          </>
        ) : null}
      </div>
    </div>
  );
}

export default App;
