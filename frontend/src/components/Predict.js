import React, { useState, useRef, useEffect } from "react";
import { motion } from "framer-motion";
import Webcam from "react-webcam";
import { GoogleGenerativeAI } from "@google/generative-ai";
import ReactMarkdown from "react-markdown";
import { jsPDF } from "jspdf";
import Feedback from "./Feedback";
import "../index.css";

const ConfidenceMeter = ({ confidence }) => {
  const [animatedValue, setAnimatedValue] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedValue(confidence * 100);
    }, 100);
    return () => clearTimeout(timer);
  }, [confidence]);

  const getColor = (value) => {
    if (value <= 30) return "#4ade80"; // Green
    if (value <= 60) return "#fbbf24"; // Yellow
    return "#ef4444"; // Red
  };

  const getLabel = (value) => {
    if (value <= 30) return "Healthy";
    if (value <= 60) return "Early signs";
    return "Likely disease (needs attention)";
  };

  return (
    <div className="w-full max-w-md mx-auto mb-6">
      <div className="relative h-8 bg-gray-200 rounded-full overflow-hidden">
        <motion.div
          initial={{ width: "0%" }}
          animate={{ width: `${animatedValue}%` }}
          transition={{ duration: 1, ease: "easeOut" }}
          className="h-full rounded-full"
          style={{ backgroundColor: getColor(animatedValue) }}
        />
        <div className="absolute top-0 left-0 w-full h-full flex items-center justify-center text-sm font-semibold text-gray-700">
          {animatedValue.toFixed(1)}%
        </div>
      </div>
      <div
        className="mt-2 text-center text-sm font-medium"
        style={{ color: getColor(animatedValue) }}
      >
        {getLabel(animatedValue)}
      </div>
      <div className="flex justify-between mt-4 text-xs text-black font-semibold ">
        <span>0%</span>
        <span>30%</span>
        <span>60%</span>
        <span>100%</span>
      </div>
      <div className="flex justify-between px-1 text-xs font-semibold">
        <span className="text-green-500">Healthy</span>
        <span className="text-yellow-500">Early signs</span>
        <span className="text-red-500">Needs attention</span>
      </div>
    </div>
  );
};

function Predict() {
  const [file, setFile] = useState(null);
  // const [prediction, setPrediction] = useState("");
  const [imagePreview, setImagePreview] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showCamera, setShowCamera] = useState(false);
  const [recommendations, setRecommendations] = useState("");
  const [predictions, setPredictions] = useState([]);
  const [error, setError] = useState(null);
  const [patientInfo, setPatientInfo] = useState({
    name: "",
    age: "",
    sex: "other",
  });
  const [formErrors, setFormErrors] = useState({
    name: "",
    age: "",
    sex: "",
  });
  const webcamRef = useRef(null);
  const resultsRef = useRef(null);
  const reportRef = useRef(null);
  const [showFeedback, setShowFeedback] = useState(false);
  const [currentPredictionId, setCurrentPredictionId] = useState(null);

  // Add scroll to results when they're available
  useEffect(() => {
    if ((predictions.length > 0 || recommendations) && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [predictions, recommendations]); // Changed from [prediction, recommendations]

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      // Check file type
      const validTypes = ["image/jpeg", "image/png", "image/jpg"];
      if (!validTypes.includes(selectedFile.type)) {
        setError("Please select a valid image file (JPEG, PNG)");
        return;
      }
      // Check file size (max 5MB)
      if (selectedFile.size > 5 * 1024 * 1024) {
        setError("File size should be less than 5MB");
        return;
      }
      setFile(selectedFile);
      setImagePreview(URL.createObjectURL(selectedFile));
      setError(null);
    }
  };

  const captureImage = () => {
    const imageSrc = webcamRef.current.getScreenshot();
    setImagePreview(imageSrc);
    // Convert base64 to file
    fetch(imageSrc)
      .then((res) => res.blob())
      .then((blob) => {
        const file = new File([blob], "webcam-capture.jpg", {
          type: "image/jpeg",
        });
        setFile(file);
        setError(null);
      });
    setShowCamera(false);
  };

  const getRecommendations = async (condition) => {
    try {
      const apiKey = process.env.REACT_APP_GEMINI_API_KEY;
      if (!apiKey) {
        throw new Error("Gemini API key is not configured");
      }

      const genAI = new GoogleGenerativeAI(apiKey);
      const model = genAI.getGenerativeModel({
        model: "gemini-1.5-pro-latest",
      });

      const prompt = `Given the skin condition "${condition}", please provide:
      1. Brief description of the condition
      2. Dietary recommendations
      3. Lifestyle changes
      4. Skincare routine suggestions
      5. When to seek medical attention
      Please format the response in a clear, structured way.`;

      const result = await model.generateContent(prompt);
      const response = await result.response;
      const text = response.text();

      if (!text) {
        throw new Error("Empty response from Gemini API");
      }

      setRecommendations(text);
      return text;
    } catch (error) {
      console.error("Error getting recommendations:", error);
      let errorMessage =
        "Unable to fetch recommendations. Please try again later.";

      if (
        error.message?.includes("API key expired") ||
        error.message?.includes("API_KEY_INVALID")
      ) {
        errorMessage =
          "The API key has expired. Please contact support to get a new API key.";
      } else if (error.message?.includes("API key")) {
        errorMessage =
          "There's an issue with the API key configuration. Please check your settings.";
      }

      setRecommendations(errorMessage);
      return errorMessage;
    }
  };

  const validateForm = () => {
    let isValid = true;
    const errors = {
      name: "",
      age: "",
      sex: "",
    };

    if (!patientInfo.name.trim()) {
      errors.name = "Name is required";
      isValid = false;
    }

    if (!patientInfo.age) {
      errors.age = "Age is required";
      isValid = false;
    } else if (
      isNaN(patientInfo.age) ||
      patientInfo.age < 0 ||
      patientInfo.age > 150
    ) {
      errors.age = "Please enter a valid age";
      isValid = false;
    }

    if (!patientInfo.sex) {
      errors.sex = "Sex is required";
      isValid = false;
    }

    setFormErrors(errors);
    return isValid;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    // Validate form first
    if (!validateForm()) {
      setError("Please fill in all required patient information correctly.");
      return;
    }

    if (!file) {
      setError("Please select an image first.");
      return;
    }

    setIsLoading(true);
    setError(null);
    setPredictions([]); // Reset predictions
    setRecommendations(""); // Reset recommendations

    const formData = new FormData();
    formData.append("file", file);

    try {
      // First check if the backend is healthy
      const healthCheck = await fetch(
        `${process.env.REACT_APP_BACKEND_URL.replace(/\/$/, "")}/health`
      );
      if (!healthCheck.ok) {
        throw new Error("Backend service is not available");
      }

      const response = await fetch(
        `${process.env.REACT_APP_BACKEND_URL}/predict`,
        {
          method: "POST",
          body: formData,
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Network response was not ok");
      }

      const data = await response.json();

      // Ensure predictions is always an array
      const receivedPredictions = Array.isArray(data.predictions)
        ? data.predictions
        : [];

      setPredictions(receivedPredictions);

      // Only get recommendations if we have predictions
      if (receivedPredictions.length > 0) {
        try {
          const recommendationsText = await getRecommendations(
            receivedPredictions[0].label
          );
          setRecommendations(recommendationsText);
        } catch (error) {
          console.error("Error getting recommendations:", error);
          setError(
            "Recommendations are temporarily unavailable. You can try downloading the report later."
          );
        }
      }

      // Store user prediction if user is logged in
      const user = JSON.parse(localStorage.getItem("user"));
      const token = localStorage.getItem("authToken");

      if (user && token && data.image_id) {
        try {
          // Get top 3 predictions with confidence
          const topPredictions = receivedPredictions
            .slice(0, 3)
            .map((pred) => ({
              label: pred.label,
              confidence: pred.confidence,
            }));

          const response = await fetch(
            `${process.env.REACT_APP_BACKEND_URL}/auth/store-prediction`,
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
              },
              body: JSON.stringify({
                email: user.email,
                image_id: data.image_id,
                predictions: topPredictions,
                timestamp: new Date().toISOString(),
              }),
            }
          );

          if (!response.ok) {
            throw new Error("Failed to store prediction");
          }

          const result = await response.json();
          if (!result.success) {
            throw new Error(result.message || "Failed to store prediction");
          }
          setCurrentPredictionId(data.image_id);
        } catch (error) {
          console.error("Error storing prediction:", error);
        }
      }
    } catch (error) {
      console.error("Error:", error);
      setError(error.message || "Error occurred during prediction");
      setPredictions([]);
      setRecommendations("");
    } finally {
      setIsLoading(false);
    }
  };

  const formatRecommendations = (text) => {
    let formattedText = text.replace(/##/g, "").replace(/\*\*/g, "");

    formattedText = formattedText.replace(/(\d+)\.\s+([^\n]+)/g, "## $1. $2");

    return formattedText;
  };

  const handleFeedbackSubmit = async (feedbackData) => {
    try {
      const user = JSON.parse(localStorage.getItem("user"));
      const token = localStorage.getItem("authToken");

      if (!user || !token) {
        console.error("User not logged in");
        return;
      }

      const response = await fetch(
        `${process.env.REACT_APP_BACKEND_URL}/auth/store-feedback`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            ...feedbackData,
            prediction_id: currentPredictionId,
          }),
        }
      );

      if (!response.ok) {
        throw new Error("Failed to store feedback");
      }

      const result = await response.json();
      if (!result.success) {
        throw new Error(result.message || "Failed to store feedback");
      }
    } catch (error) {
      console.error("Error storing feedback:", error);
    }
  };

  const handleDownloadReport = async () => {
    if (!reportRef.current || !recommendations) {
      setError("Please wait for recommendations to be generated.");
      return;
    }

    try {
      setIsLoading(true);

      // Create a new PDF document
      const pdf = new jsPDF("p", "mm", "a4");
      const pageWidth = pdf.internal.pageSize.width;
      const margin = 20;
      const maxWidth = pageWidth - 2 * margin;

      // Helper function to wrap text
      const splitTextToSize = (text, fontSize, maxLineWidth) => {
        pdf.setFontSize(fontSize);
        return pdf.splitTextToSize(text, maxLineWidth);
      };

      // Add header
      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(24);
      pdf.setTextColor(89, 44, 122);
      pdf.text("DermAI Medical Report", pageWidth / 2, margin, {
        align: "center",
      });

      // Add report metadata
      pdf.setFont("helvetica", "normal");
      pdf.setFontSize(10);
      pdf.setTextColor(128, 128, 128);
      const reportDate = new Date().toLocaleDateString();
      const reportId = Math.random().toString(36).substr(2, 9).toUpperCase();
      pdf.text(`Report Date: ${reportDate}`, margin, margin + 15);
      pdf.text(`Report ID: ${reportId}`, pageWidth - margin, margin + 15, {
        align: "right",
      });

      // Add patient information section
      pdf.setFillColor(248, 250, 252);
      pdf.roundedRect(margin, margin + 20, maxWidth, 25, 2, 2, "F");

      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(12);
      pdf.setTextColor(51, 51, 51);
      pdf.text("Patient Information", margin + 5, margin + 30);

      pdf.setFont("helvetica", "normal");
      pdf.setFontSize(10);
      const patientDetails = [
        `Name: ${patientInfo.name || "N/A"}`,
        `Age: ${patientInfo.age || "N/A"}`,
        `Sex: ${
          patientInfo.sex.charAt(0).toUpperCase() + patientInfo.sex.slice(1)
        }`,
      ];
      pdf.text(patientDetails, margin + 5, margin + 38);

      let yPos = margin + 55;

      // Add image section
      if (imagePreview) {
        const img = new Image();
        img.src = imagePreview;

        await new Promise((resolve) => {
          img.onload = () => {
            const imgWidth = 100;
            const imgHeight = (img.height * imgWidth) / img.width;
            const xPos = (pageWidth - imgWidth) / 2;
            pdf.addImage(img, "JPEG", xPos, yPos, imgWidth, imgHeight);
            resolve();
          };
        });
        yPos += 90;
      }

      // Add diagnosis section
      pdf.setFillColor(243, 232, 255);
      pdf.roundedRect(margin, yPos, maxWidth, 50, 3, 3, "F");

      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(16);
      pdf.setTextColor(89, 44, 122);
      pdf.text("Primary Diagnosis", margin + 5, yPos + 10);

      const topPrediction = predictions[0];
      if (topPrediction) {
        pdf.setFont("helvetica", "normal");
        pdf.setFontSize(12);
        pdf.setTextColor(51, 51, 51);
        pdf.text(
          `${topPrediction.label} (${(topPrediction.confidence * 100).toFixed(
            1
          )}% confidence)`,
          margin + 5,
          yPos + 25
        );

        if (topPrediction.subcategories?.length > 0) {
          pdf.setFontSize(11);
          pdf.text("Possible subconditions:", margin + 5, yPos + 35);
          const subconditions = topPrediction.subcategories.join(", ");
          const subLines = splitTextToSize(subconditions, 11, maxWidth - 15);
          pdf.text(subLines, margin + 5, yPos + 42);
        }
      }

      yPos += 60;

      // Add recommendations section
      if (recommendations) {
        pdf.setFont("helvetica", "bold");
        pdf.setFontSize(16);
        pdf.setTextColor(89, 44, 122);
        pdf.text("Recommendations", margin, yPos);
        yPos += 15;

        // Define sections to extract from recommendations
        const sections = [
          { title: "Brief Description", color: [255, 240, 245] },
          { title: "Dietary Recommendations", color: [240, 253, 244] },
          { title: "Lifestyle Changes", color: [238, 242, 255] },
          { title: "Skincare Routine", color: [255, 247, 237] },
          { title: "When to Seek Medical Attention", color: [243, 232, 255] },
        ];

        // Split recommendations into paragraphs
        const paragraphs = recommendations.split("\n\n");

        // Process each section
        sections.forEach((section, index) => {
          // Find the section content
          let sectionContent = "";
          let foundSection = false;

          for (let i = 0; i < paragraphs.length; i++) {
            const paragraph = paragraphs[i];
            if (
              paragraph.includes(`${index + 1}.`) ||
              paragraph.toLowerCase().includes(section.title.toLowerCase())
            ) {
              foundSection = true;
              sectionContent = paragraph;
              // Include following paragraphs until next section or end
              let nextIndex = i + 1;
              while (
                nextIndex < paragraphs.length &&
                !paragraphs[nextIndex].match(/^\d+\./)
              ) {
                sectionContent += "\n\n" + paragraphs[nextIndex];
                nextIndex++;
              }
              break;
            }
          }

          if (foundSection) {
            if (yPos > 250) {
              pdf.addPage();
              yPos = margin;
            }

            // Format the content with markdown-like styling
            const formattedContent = sectionContent
              .replace(/\*\*(.*?)\*\*/g, "$1") // Remove ** markers but keep text bold
              .replace(/^\s*[-•]\s*/gm, "  • ") // Format bullet points
              .trim();

            // Calculate text dimensions for proper box sizing
            const contentLines = splitTextToSize(
              formattedContent,
              9,
              maxWidth - 20
            ); // Reduced width for padding
            const titleHeight = 15;
            const lineHeight = 4.5;
            const verticalPadding = 15;
            const boxHeight =
              titleHeight +
              contentLines.length * lineHeight +
              verticalPadding * 2;

            // Draw colored box with proper padding
            pdf.setFillColor(...section.color);
            pdf.roundedRect(margin, yPos, maxWidth, boxHeight, 3, 3, "F");

            // Add section title
            pdf.setFont("helvetica", "bold");
            pdf.setFontSize(12);
            pdf.setTextColor(51, 51, 51);
            pdf.text(section.title, margin + 10, yPos + 12);

            // Add content with proper formatting
            pdf.setFont("helvetica", "normal");
            pdf.setFontSize(9);

            // Process content line by line for formatting
            let currentY = yPos + titleHeight + 5;
            contentLines.forEach((line) => {
              // Check for bullet points
              if (line.startsWith("  • ")) {
                pdf.setFont("helvetica", "normal");
              } else if (line.match(/^[A-Z].*:/)) {
                // Headers or important points
                pdf.setFont("helvetica", "bold");
              } else {
                pdf.setFont("helvetica", "normal");
              }

              pdf.text(line, margin + 10, currentY);
              currentY += lineHeight;
            });

            yPos += boxHeight + 10; // Add spacing between sections
          }
        });
      }

      // Add disclaimer
      if (yPos > 250) {
        pdf.addPage();
        yPos = margin;
      }

      pdf.setFillColor(248, 250, 252);
      pdf.roundedRect(margin, yPos, maxWidth, 20, 3, 3, "F");
      pdf.setFont("helvetica", "italic");
      pdf.setFontSize(9);
      pdf.setTextColor(107, 114, 128);
      const disclaimer =
        "This information is for general knowledge and should not be considered medical advice. Always consult a dermatologist or other qualified healthcare professional for diagnosis and treatment of any specific skin condition.";
      const disclaimerLines = splitTextToSize(disclaimer, 9, maxWidth - 10);
      pdf.text(disclaimerLines, margin + 5, yPos + 10);

      // Add footer
      pdf.setFont("helvetica", "italic");
      pdf.setFontSize(8);
      pdf.setTextColor(128, 128, 128);
      pdf.text(
        "Generated by DermAI - For professional medical review only",
        pageWidth / 2,
        pdf.internal.pageSize.height - 10,
        { align: "center" }
      );

      // Save the PDF
      pdf.save("dermai-medical-report.pdf");

      // Show feedback popup after 1 second
      setTimeout(() => {
        setShowFeedback(true);
      }, 1000);
    } catch (error) {
      console.error("Error generating PDF:", error);
      setError("Failed to generate PDF report");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col">
      <div className="flex-grow bg-gradient-to-r from-purple-50 to-blue-50 page-wrapper">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="max-w-4xl mx-auto px-4 py-8"
        >
          <h1 className="text-4xl font-bold text-purple-700 text-center mb-8 mt-10 lg:mt-0">
            Skin Condition Analysis
          </h1>

          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4">
              <span className="block sm:inline">{error}</span>
            </div>
          )}

          <div className="bg-white rounded-xl shadow-xl p-6 mb-8">
            {/* Patient Information Section */}
            <div className="mb-6">
              <h2 className="text-2xl font-semibold text-purple-700 mb-4">
                Patient Information
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-gray-700 text-sm font-bold mb-2">
                    Full Name <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={patientInfo.name}
                    onChange={(e) =>
                      setPatientInfo({ ...patientInfo, name: e.target.value })
                    }
                    className={`w-full p-2 border rounded-lg focus:outline-none focus:border-purple-700 ${
                      formErrors.name ? "border-red-500" : ""
                    }`}
                    placeholder="Enter patient name"
                  />
                  {formErrors.name && (
                    <p className="text-red-500 text-xs mt-1">
                      {formErrors.name}
                    </p>
                  )}
                </div>
                <div>
                  <label className="block text-gray-700 text-sm font-bold mb-2">
                    Age <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="number"
                    value={patientInfo.age}
                    onChange={(e) =>
                      setPatientInfo({ ...patientInfo, age: e.target.value })
                    }
                    className={`w-full p-2 border rounded-lg focus:outline-none focus:border-purple-700 ${
                      formErrors.age ? "border-red-500" : ""
                    }`}
                    placeholder="Enter age"
                    min="0"
                    max="150"
                  />
                  {formErrors.age && (
                    <p className="text-red-500 text-xs mt-1">
                      {formErrors.age}
                    </p>
                  )}
                </div>
                <div>
                  <label className="block text-gray-700 text-sm font-bold mb-2">
                    Sex <span className="text-red-500">*</span>
                  </label>
                  <select
                    value={patientInfo.sex}
                    onChange={(e) =>
                      setPatientInfo({ ...patientInfo, sex: e.target.value })
                    }
                    className={`w-full p-2 border rounded-lg focus:outline-none focus:border-purple-700 ${
                      formErrors.sex ? "border-red-500" : ""
                    }`}
                  >
                    <option value="male">Male</option>
                    <option value="female">Female</option>
                    <option value="other">Other</option>
                  </select>
                  {formErrors.sex && (
                    <p className="text-red-500 text-xs mt-1">
                      {formErrors.sex}
                    </p>
                  )}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div className="relative">
                {showCamera ? (
                  <div className="relative">
                    <Webcam
                      audio={false}
                      ref={webcamRef}
                      screenshotFormat="image/jpeg"
                      className="w-full rounded-lg"
                    />
                    <button
                      onClick={captureImage}
                      className="absolute bottom-4 left-1/2 transform -translate-x-1/2 bg-purple-700 text-white px-4 py-2 rounded-lg hover:bg-purple-800 transition duration-300"
                    >
                      Capture
                    </button>
                  </div>
                ) : imagePreview ? (
                  <img
                    src={imagePreview}
                    alt="Preview"
                    className="w-full h-64 object-cover rounded-lg"
                  />
                ) : (
                  <div className="w-full h-64 bg-gray-100 rounded-lg flex items-center justify-center">
                    <p className="text-gray-500">No image selected</p>
                  </div>
                )}
              </div>
              <div>
                <h2 className="text-2xl font-semibold text-purple-700 mb-4">
                  Upload Image
                </h2>
                <div className="space-y-4">
                  <button
                    onClick={() => setShowCamera(!showCamera)}
                    className="w-full bg-purple-100 text-purple-700 px-4 py-2 rounded-lg hover:bg-purple-200 transition duration-300"
                  >
                    {showCamera ? "Hide Camera" : "Use Camera"}
                  </button>
                  <div className="relative">
                    <input
                      type="file"
                      id="file-upload"
                      onChange={handleFileChange}
                      className="hidden"
                      accept="image/*"
                    />
                    <label
                      htmlFor="file-upload"
                      className="w-full bg-purple-700 text-white px-4 py-2 rounded-lg hover:bg-purple-800 transition duration-300 cursor-pointer block text-center"
                    >
                      Choose File
                    </label>
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-6 text-center">
              <button
                onClick={handleSubmit}
                disabled={
                  !file ||
                  isLoading ||
                  !patientInfo.name ||
                  !patientInfo.age ||
                  !patientInfo.sex
                }
                className={`bg-purple-700 text-white px-8 py-3 rounded-lg transition duration-300 ${
                  !file ||
                  isLoading ||
                  !patientInfo.name ||
                  !patientInfo.age ||
                  !patientInfo.sex
                    ? "opacity-50 cursor-not-allowed"
                    : "hover:bg-purple-800"
                }`}
              >
                {isLoading ? "Analyzing..." : "Analyze Image"}
              </button>
            </div>
          </div>

          {(predictions.length > 0 || recommendations) && (
            <motion.div
              ref={resultsRef}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-white rounded-xl shadow-xl p-6"
            >
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-2xl font-semibold text-purple-700">
                  Diagnosis Results
                </h2>
              </div>

              <div ref={reportRef}>
                {predictions.length > 0 && (
                  <div className="mb-6">
                    <ConfidenceMeter confidence={predictions[0].confidence} />
                    <div className="p-4 bg-purple-50 rounded-lg mb-3">
                      <h3 className="text-lg font-semibold text-purple-700">
                        Primary Diagnosis: {predictions[0].label}
                      </h3>
                      {predictions[0].subcategories && (
                        <div className="mt-2">
                          <p className="text-sm font-medium text-gray-600">
                            Possible subconditions:
                          </p>
                          <ul className="list-disc pl-6 mt-1">
                            {predictions[0].subcategories?.map((sub, idx) => (
                              <li key={idx} className="text-sm text-gray-700">
                                {sub}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {recommendations && (
                  <div>
                    <h2 className="text-2xl font-semibold text-purple-700 mb-4">
                      Recommendations
                    </h2>
                    <div className="prose prose-purple max-w-none">
                      <div className="space-y-4 text-gray-700">
                        <ReactMarkdown
                          components={{
                            h2: ({ children }) => (
                              <h2 className="text-xl font-semibold text-purple-700 mt-6 mb-3">
                                {children}
                              </h2>
                            ),
                            p: ({ children }) => (
                              <p className="text-gray-700 mb-4">{children}</p>
                            ),
                            ul: ({ children }) => (
                              <ul className="list-disc pl-6 mb-4">
                                {children}
                              </ul>
                            ),
                            li: ({ children }) => (
                              <li className="text-gray-700 mb-2">{children}</li>
                            ),
                          }}
                        >
                          {formatRecommendations(recommendations)}
                        </ReactMarkdown>
                      </div>
                    </div>
                  </div>
                )}

                <div className="mt-6 flex justify-center">
                  <button
                    onClick={handleDownloadReport}
                    disabled={isLoading || !recommendations}
                    className={`${
                      isLoading || !recommendations
                        ? "bg-gray-400 cursor-not-allowed"
                        : "bg-green-600 hover:bg-green-700"
                    } text-white px-4 py-2 rounded-lg transition duration-300 flex items-center`}
                    title={
                      !recommendations
                        ? "Waiting for recommendations..."
                        : "Download Report"
                    }
                  >
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      className="h-5 w-5 mr-2"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
                      />
                    </svg>
                    {!recommendations
                      ? "Generating Recommendations..."
                      : "Download Report"}
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </motion.div>
      </div>

      <Feedback
        isOpen={showFeedback}
        onClose={() => setShowFeedback(false)}
        onSubmit={handleFeedbackSubmit}
      />
    </div>
  );
}

export default Predict;
