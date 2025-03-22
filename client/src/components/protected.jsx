import React, { useState } from "react";
import axios from "axios";

const fetchProtectedData = async () => {
  const token = localStorage.getItem("token");
  if (!token) {
    alert("Please log in first!");
    return;
  }

  const res = await axios.get("http://localhost:8080/api/protected", {
    headers: { Authorization: `Bearer ${token}` },
  });

  console.log(res.data);
}