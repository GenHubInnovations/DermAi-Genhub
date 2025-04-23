import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";

const History = () => {
  const [predictions, setPredictions] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const user = JSON.parse(localStorage.getItem("user") || "null");

  useEffect(() => {
    const fetchUserPredictions = async () => {
      if (!user) return;

      try {
        const token = localStorage.getItem("authToken");
        if (!token) {
          setError("Authentication token not found");
          return;
        }

        const response = await fetch(
          `${process.env.REACT_APP_BACKEND_URL}/auth/user-predictions`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        if (!response.ok) {
          throw new Error("Failed to fetch predictions");
        }

        const data = await response.json();
        if (data.success) {
          setPredictions(data.predictions);
        } else {
          setError(data.message || "Failed to load predictions");
        }
      } catch (error) {
        console.error("Error fetching predictions:", error);
        setError("Failed to load your prediction history");
      } finally {
        setIsLoading(false);
      }
    };

    fetchUserPredictions();
  }, [user]);

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString() + " " + date.toLocaleTimeString();
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-gradient-to-r from-blue-50 to-purple-50 pt-24 px-4">
        <div className="max-w-4xl mx-auto bg-white rounded-xl shadow-md overflow-hidden p-6">
          <h1 className="text-3xl font-bold text-purple-700 mb-4">
            Prediction History
          </h1>
          <p className="text-gray-600 mb-4">
            Please log in to view your prediction history.
          </p>
          <Link
            to="/login"
            className="bg-purple-700 text-white px-4 py-2 rounded-md hover:bg-purple-800"
          >
            Login
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-r from-blue-50 to-purple-50 pt-24 px-4">
      <div className="max-w-4xl mx-auto bg-white rounded-xl shadow-md overflow-hidden p-6">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold text-purple-700">
            Prediction History
          </h1>
          <Link to="/dashboard" className="text-purple-700 hover:underline">
            Back to Dashboard
          </Link>
        </div>

        {isLoading ? (
          <div className="text-center py-8">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-purple-700"></div>
            <p className="mt-2 text-gray-600">
              Loading your prediction history...
            </p>
          </div>
        ) : error ? (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4">
            <span className="block sm:inline">{error}</span>
          </div>
        ) : predictions.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {predictions.map((prediction, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                className="bg-purple-50 p-6 rounded-lg shadow hover:shadow-lg transition-shadow"
              >
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <h3 className="text-lg font-semibold text-purple-700">
                      {prediction.predictions[0]?.label || "Unknown Condition"}
                    </h3>
                    <p className="text-sm text-gray-500">
                      {formatDate(prediction.timestamp)}
                    </p>
                  </div>
                </div>

                <div className="space-y-4">
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-2">
                      Confidence Score:
                    </p>
                    <div className="flex items-center">
                      <div className="w-full bg-gray-200 rounded-full h-2.5">
                        <div
                          className="bg-purple-700 h-2.5 rounded-full"
                          style={{
                            width: `${
                              (prediction.predictions[0]?.confidence || 0) * 100
                            }%`,
                          }}
                        ></div>
                      </div>
                      <span className="ml-2 text-sm text-gray-600">
                        {(
                          (prediction.predictions[0]?.confidence || 0) * 100
                        ).toFixed(1)}
                        %
                      </span>
                    </div>
                  </div>

                  {prediction.predictions[0]?.subcategories && (
                    <div>
                      <p className="text-sm font-medium text-gray-700 mb-2">
                        Possible Subcategories:
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {prediction.predictions[0].subcategories.map(
                          (sub, idx) => (
                            <span
                              key={idx}
                              className="bg-purple-100 text-purple-800 px-2 py-1 rounded-full text-xs"
                            >
                              {sub}
                            </span>
                          )
                        )}
                      </div>
                    </div>
                  )}

                  {prediction.image_url && (
                    <div className="mt-4">
                      <img
                        src={prediction.image_url}
                        alt="Skin condition"
                        className="w-full h-48 object-cover rounded-md"
                      />
                    </div>
                  )}
                </div>
              </motion.div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8">
            <p className="text-gray-600">No prediction history found.</p>
            <Link
              to="/predict"
              className="mt-4 inline-block bg-purple-700 text-white px-4 py-2 rounded-md hover:bg-purple-800"
            >
              Make a New Diagnosis
            </Link>
          </div>
        )}
      </div>
    </div>
  );
};

export default History;
