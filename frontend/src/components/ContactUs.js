import React, { useState } from "react";
import { Mail, Phone, User, MessageCircle } from "lucide-react"; // Import icons
import axios from "axios";
import { toast } from "react-toastify";

function ContactUs() {
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    phone: "",
    message: "",
  });
  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showSuccessModal, setShowSuccessModal] = useState(false);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    });

    // Clear error when user starts typing
    if (errors[name]) {
      setErrors({
        ...errors,
        [name]: "",
      });
    }
  };

  const validateForm = () => {
    const newErrors = {};

    if (!formData.name.trim()) {
      newErrors.name = "Name is required";
    }

    if (!formData.email.trim()) {
      newErrors.email = "Email is required";
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = "Email is invalid";
    }

    if (!formData.phone.trim()) {
      newErrors.phone = "Phone number is required";
    }

    if (!formData.message.trim()) {
      newErrors.message = "Message is required";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await axios.post(
        `${process.env.REACT_APP_BACKEND_URL}/contact`,
        formData
      );

      if (response.data.success) {
        setShowSuccessModal(true);
        setFormData({
          name: "",
          email: "",
          phone: "",
          message: "",
        });
      }
    } catch (error) {
      console.error("Error submitting contact form:", error);
      toast.error(
        error.response?.data?.error ||
          "Failed to submit your message. Please try again."
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <>
      <div className="min-h-[80vh] flex items-center justify-center bg-gradient-to-r from-blue-50 to-purple-50 p-6">
        <div className="w-full max-w-2xl bg-white p-8 rounded-xl shadow-lg">
          <h1 className="text-3xl font-bold text-purple-700 text-center mb-6 mt-16 lg:mt-0">
            Contact Us
          </h1>
          <div className="flex flex-col md:flex-row">
            <div className="md:w-1/2 mb-6 md:mb-0">
              <img
                src="/contactus.jpg"
                alt="Contact Us"
                className="rounded-lg mx-auto"
              />
            </div>
            <div className="md:w-1/2">
              <form onSubmit={handleSubmit}>
                <div className="mb-4 flex items-center border border-gray-300 rounded-lg">
                  <User className="w-5 h-5 text-gray-500 ml-3" />
                  <input
                    id="name"
                    name="name"
                    type="text"
                    placeholder="Enter your name"
                    required
                    value={formData.name}
                    onChange={handleChange}
                    className={`w-full p-3 border-0 focus:outline-none focus:ring-2 focus:ring-purple-500 ${
                      errors.name ? "ring-2 ring-red-500" : ""
                    }`}
                  />
                </div>
                {errors.name && (
                  <p className="text-red-500 text-xs mb-2">{errors.name}</p>
                )}

                <div className="mb-4 flex items-center border border-gray-300 rounded-lg">
                  <Mail className="w-5 h-5 text-gray-500 ml-3" />
                  <input
                    id="email"
                    name="email"
                    type="email"
                    placeholder="Enter your email"
                    required
                    value={formData.email}
                    onChange={handleChange}
                    className={`w-full p-3 border-0 focus:outline-none focus:ring-2 focus:ring-purple-500 ${
                      errors.email ? "ring-2 ring-red-500" : ""
                    }`}
                  />
                </div>
                {errors.email && (
                  <p className="text-red-500 text-xs mb-2">{errors.email}</p>
                )}

                <div className="mb-4 flex items-center border border-gray-300 rounded-lg">
                  <Phone className="w-5 h-5 text-gray-500 ml-3" />
                  <input
                    id="phone"
                    name="phone"
                    type="tel"
                    placeholder="Enter your phone number"
                    required
                    value={formData.phone}
                    onChange={handleChange}
                    className={`w-full p-3 border-0 focus:outline-none focus:ring-2 focus:ring-purple-500 ${
                      errors.phone ? "ring-2 ring-red-500" : ""
                    }`}
                  />
                </div>
                {errors.phone && (
                  <p className="text-red-500 text-xs mb-2">{errors.phone}</p>
                )}

                <div className="mb-4 flex items-center border border-gray-300 rounded-lg">
                  <MessageCircle className="w-5 h-5 text-gray-500 ml-3" />
                  <textarea
                    id="message"
                    name="message"
                    placeholder="Your message here"
                    required
                    value={formData.message}
                    onChange={handleChange}
                    className={`w-full p-3 border-0 focus:outline-none focus:ring-2 focus:ring-purple-500 ${
                      errors.message ? "ring-2 ring-red-500" : ""
                    }`}
                    rows="4"
                  />
                </div>
                {errors.message && (
                  <p className="text-red-500 text-xs mb-2">{errors.message}</p>
                )}

                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full bg-purple-700 text-white py-3 rounded-lg hover:bg-purple-800 transition duration-300 shadow-lg hover:shadow-xl disabled:opacity-50"
                >
                  {isSubmitting ? "Sending..." : "Submit"}
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>

      {/* Success Modal */}
      {showSuccessModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl p-6 max-w-md w-full">
            <div className="text-center">
              <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
                <svg
                  className="h-6 w-6 text-green-600"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M5 13l4 4L19 7"
                  />
                </svg>
              </div>
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                Message Sent Successfully!
              </h3>
              <p className="text-sm text-gray-500 mb-4">
                Thank you for contacting us. Our team will reach out to you
                soon.
              </p>
              <button
                onClick={() => setShowSuccessModal(false)}
                className="w-full bg-purple-700 text-white py-2 rounded-lg hover:bg-purple-800 transition duration-300"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default ContactUs;
