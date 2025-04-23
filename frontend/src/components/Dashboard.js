import React, { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";

const Dashboard = () => {
  const user = JSON.parse(localStorage.getItem("user") || "null");
  const isAdmin = user?.role === "admin";
  const [predictions, setPredictions] = useState([]);
  const [users, setUsers] = useState([]);
  const [feedbacks, setFeedbacks] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const dataFetchedRef = useRef(false);
  const [stats, setStats] = useState({
    total: 0,
    lastWeek: 0,
    mostCommon: null,
  });

  useEffect(() => {
    const fetchData = async () => {
      if (!user) {
        console.log("No user found in localStorage");
        return;
      }

      // Prevent multiple fetches
      if (dataFetchedRef.current) {
        console.log("Data already fetched, skipping");
        return;
      }

      try {
        const token = localStorage.getItem("authToken");
        if (!token) {
          console.log("No token found in localStorage");
          return;
        }

        console.log(
          "Fetching predictions from:",
          `${process.env.REACT_APP_BACKEND_URL}/auth/user-predictions`
        );

        // Fetch predictions
        const predictionsResponse = await fetch(
          `${process.env.REACT_APP_BACKEND_URL}/auth/user-predictions`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        console.log("Predictions response status:", predictionsResponse.status);

        if (!predictionsResponse.ok) {
          const errorText = await predictionsResponse.text();
          console.error("Failed to fetch predictions:", errorText);
          throw new Error(
            `Failed to fetch predictions: ${predictionsResponse.status} ${errorText}`
          );
        }

        const predictionsData = await predictionsResponse.json();
        if (predictionsData.success) {
          setPredictions(predictionsData.predictions);
        }

        // Fetch admin data if user is admin
        if (isAdmin) {
          console.log("User is admin, fetching additional data");

          // Fetch users
          console.log(
            "Fetching users from:",
            `${process.env.REACT_APP_BACKEND_URL}/auth/users`
          );
          const usersResponse = await fetch(
            `${process.env.REACT_APP_BACKEND_URL}/auth/users`,
            {
              headers: {
                Authorization: `Bearer ${token}`,
              },
            }
          );

          console.log("Users response status:", usersResponse.status);

          if (usersResponse.ok) {
            const usersData = await usersResponse.json();
            if (usersData.success) {
              setUsers(usersData.users);
              console.log("Users data loaded:", usersData.users.length);
            }
          } else {
            const errorText = await usersResponse.text();
            console.error("Failed to fetch users:", errorText);
          }

          // Fetch feedbacks
          console.log(
            "Fetching feedbacks from:",
            `${process.env.REACT_APP_BACKEND_URL}/auth/feedbacks`
          );
          const feedbacksResponse = await fetch(
            `${process.env.REACT_APP_BACKEND_URL}/auth/feedbacks`,
            {
              headers: {
                Authorization: `Bearer ${token}`,
              },
            }
          );

          console.log("Feedbacks response status:", feedbacksResponse.status);

          if (feedbacksResponse.ok) {
            const feedbacksData = await feedbacksResponse.json();
            if (feedbacksData.success) {
              setFeedbacks(feedbacksData.feedbacks);
              console.log(
                "Feedbacks data loaded:",
                feedbacksData.feedbacks.length
              );
            }
          } else {
            const errorText = await feedbacksResponse.text();
            console.error("Failed to fetch feedbacks:", errorText);
          }
        }

        // Calculate statistics
        const now = new Date();
        const lastWeek = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

        const lastWeekPredictions = predictionsData.predictions.filter(
          (p) => new Date(p.timestamp) > lastWeek
        ).length;

        // Find most common condition
        const conditions = predictionsData.predictions.reduce((acc, p) => {
          const condition = p.predictions[0]?.label;
          if (condition) {
            acc[condition] = (acc[condition] || 0) + 1;
          }
          return acc;
        }, {});

        const mostCommon = Object.entries(conditions).sort(
          (a, b) => b[1] - a[1]
        )[0];

        setStats({
          total: predictionsData.predictions.length,
          lastWeek: lastWeekPredictions,
          mostCommon: mostCommon ? mostCommon[0] : null,
        });

        // Mark data as fetched to prevent repeated API calls
        dataFetchedRef.current = true;
      } catch (error) {
        console.error("Error fetching data:", error);
        setError(error.message || "Failed to load data");
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, [user, isAdmin]);

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString() + " " + date.toLocaleTimeString();
  };

  // Add error display
  if (error) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div
          className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative"
          role="alert"
        >
          <strong className="font-bold">Error!</strong>
          <span className="block sm:inline"> {error}</span>
          <p className="mt-2">
            Please try refreshing the page or contact support if the issue
            persists.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-r from-blue-50 to-purple-50 pt-24 px-4">
      <div className="max-w-7xl mx-auto">
        <div className="bg-white rounded-xl shadow-md overflow-hidden p-6 mb-6">
          <h1 className="text-3xl font-bold text-purple-700 mb-4">Dashboard</h1>
          <p className="text-gray-600 mb-4">
            Welcome, {user?.name || "User"}!
            {isAdmin && (
              <span className="ml-2 bg-purple-100 text-purple-800 px-2 py-1 rounded-full text-xs font-semibold">
                Admin
              </span>
            )}
          </p>

          {/* Statistics Section */}
          {!isLoading && !error && predictions.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
              <div className="bg-purple-50 p-4 rounded-lg">
                <h4 className="text-sm font-semibold text-purple-700">
                  Total Diagnoses
                </h4>
                <p className="text-2xl font-bold text-purple-900">
                  {stats.total}
                </p>
              </div>
              <div className="bg-blue-50 p-4 rounded-lg">
                <h4 className="text-sm font-semibold text-blue-700">
                  Last 7 Days
                </h4>
                <p className="text-2xl font-bold text-blue-900">
                  {stats.lastWeek}
                </p>
              </div>
              {stats.mostCommon && (
                <div className="bg-green-50 p-4 rounded-lg">
                  <h4 className="text-sm font-semibold text-green-700">
                    Most Common Condition
                  </h4>
                  <p className="text-lg font-bold text-green-900 truncate">
                    {stats.mostCommon}
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Admin Tables */}
          {isAdmin && (
            <div className="space-y-6">
              {/* Users Table */}
              <div className="bg-white rounded-lg shadow overflow-hidden">
                <div className="px-4 py-5 sm:px-6">
                  <h3 className="text-lg font-medium text-gray-900">Users</h3>
                </div>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Name
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Email
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Role
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Predictions
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Feedback Count
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Last Login
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {users.map((user) => (
                        <tr key={user._id}>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-medium text-gray-900">
                              {user.name}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm text-gray-500">
                              {user.email}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span
                              className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                user.role === "admin"
                                  ? "bg-purple-100 text-purple-800"
                                  : "bg-green-100 text-green-800"
                              }`}
                            >
                              {user.role}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {user.predictions?.length || 0}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {user.feedback_count || 0}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {user.last_login
                              ? formatDate(user.last_login)
                              : "Never"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Feedback Table */}
              <div className="bg-white rounded-lg shadow overflow-hidden">
                <div className="px-4 py-5 sm:px-6">
                  <h3 className="text-lg font-medium text-gray-900">
                    Feedback
                  </h3>
                </div>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          User
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Rating
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Description
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Date
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {feedbacks.map((feedback) => (
                        <tr key={feedback._id}>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm text-gray-900">
                              {feedback.user_email}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center">
                              {[...Array(5)].map((_, i) => (
                                <span
                                  key={i}
                                  className={`text-lg ${
                                    i < feedback.rating
                                      ? "text-yellow-400"
                                      : "text-gray-300"
                                  }`}
                                >
                                  ★
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <div className="text-sm text-gray-900 max-w-md truncate">
                              {feedback.description}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {formatDate(feedback.timestamp)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* Regular User Content */}
          {!isAdmin && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
              <div className="bg-purple-50 p-4 rounded-lg shadow">
                <h3 className="text-xl font-semibold text-purple-700 mb-2">
                  Recent Activity
                </h3>
                {isLoading ? (
                  <p className="text-gray-600">
                    Loading your prediction history...
                  </p>
                ) : error ? (
                  <p className="text-red-600">{error}</p>
                ) : predictions.length > 0 ? (
                  <div className="space-y-3">
                    {predictions.slice(0, 3).map((prediction, index) => (
                      <div
                        key={index}
                        className="bg-white p-4 rounded-md shadow-sm hover:shadow-md transition-shadow duration-200"
                      >
                        <div className="flex items-start space-x-4">
                          {prediction.image_url && (
                            <img
                              src={prediction.image_url}
                              alt="Condition"
                              className="w-16 h-16 object-cover rounded-md"
                            />
                          )}
                          <div className="flex-1">
                            <p className="font-medium text-purple-700 text-lg">
                              {prediction.predictions[0]?.label ||
                                "Unknown Condition"}
                            </p>
                            <p className="text-sm text-gray-600 mt-1">
                              Confidence:{" "}
                              {(
                                (prediction.predictions[0]?.confidence || 0) *
                                100
                              ).toFixed(1)}
                              %
                            </p>
                            <p className="text-xs text-gray-500 mt-1">
                              {formatDate(prediction.timestamp)}
                            </p>
                          </div>
                        </div>
                        {prediction.predictions[0]?.subcategories && (
                          <div className="mt-2 pl-20">
                            <p className="text-sm text-gray-600">
                              Possible subconditions:
                            </p>
                            <ul className="list-disc pl-4 text-xs text-gray-500 mt-1">
                              {prediction.predictions[0].subcategories
                                .slice(0, 2)
                                .map((sub, idx) => (
                                  <li key={idx}>{sub}</li>
                                ))}
                              {prediction.predictions[0].subcategories.length >
                                2 && <li>...</li>}
                            </ul>
                          </div>
                        )}
                      </div>
                    ))}
                    {predictions.length > 3 && (
                      <Link
                        to="/history"
                        className="text-purple-700 text-sm hover:underline"
                      >
                        View all {predictions.length} predictions
                      </Link>
                    )}
                  </div>
                ) : (
                  <p className="text-gray-600">
                    No recent activity to display.
                  </p>
                )}
              </div>

              <div className="bg-blue-50 p-4 rounded-lg shadow">
                <h3 className="text-xl font-semibold text-purple-700 mb-2">
                  Quick Actions
                </h3>
                <div className="space-y-2">
                  <button className="bg-purple-700 text-white px-4 py-2 rounded-md hover:bg-purple-800 w-full">
                    <Link to="/predict">New Diagnosis</Link>
                  </button>
                  <button className="bg-blue-700 text-white px-4 py-2 rounded-md hover:bg-blue-800 w-full">
                    <Link to="/history">View History</Link>
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
