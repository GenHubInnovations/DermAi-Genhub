import React, { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import axios from "axios";
import { toast } from "react-toastify";

const ProtectedRoute = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const verifyToken = async () => {
      const token = localStorage.getItem("authToken");

      if (!token) {
        setIsLoading(false);
        return;
      }

      try {
        const response = await axios.post(
          `${
            process.env.REACT_APP_API_URL || "http://localhost:5000"
          }/auth/verify-token`,
          {
            token,
          }
        );

        if (response.data.success) {
          setIsAuthenticated(true);
        } else {
          // Token is invalid, remove from storage
          localStorage.removeItem("authToken");
          localStorage.removeItem("user");
          toast.error("Your session has expired. Please log in again.");
        }
      } catch (error) {
        localStorage.removeItem("authToken");
        localStorage.removeItem("user");
      } finally {
        setIsLoading(false);
      }
    };

    verifyToken();
  }, []);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return isAuthenticated ? children : <Navigate to="/login" />;
};

export default ProtectedRoute;
