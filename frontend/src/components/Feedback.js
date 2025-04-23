import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

const Feedback = ({ isOpen, onClose, onSubmit }) => {
  const [rating, setRating] = useState(0);
  const [description, setDescription] = useState("");
  const [hoveredRating, setHoveredRating] = useState(0);

  const handleSubmit = () => {
    if (rating === 0) {
      alert("Please select a rating");
      return;
    }
    onSubmit({ rating, description });
    setRating(0);
    setDescription("");
    onClose();
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
        >
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.8, opacity: 0 }}
            className="bg-white rounded-lg p-6 w-full max-w-md"
          >
            <h2 className="text-2xl font-semibold text-purple-700 mb-4">
              Rate Your Experience
            </h2>
            <p className="text-gray-600 mb-4">
              How would you rate your experience with DermAI?
            </p>

            <div className="flex justify-center space-x-2 mb-4">
              {[1, 2, 3, 4, 5].map((star) => (
                <button
                  key={star}
                  onClick={() => setRating(star)}
                  onMouseEnter={() => setHoveredRating(star)}
                  onMouseLeave={() => setHoveredRating(0)}
                  className="text-3xl focus:outline-none"
                >
                  <span
                    className={
                      star <= (hoveredRating || rating)
                        ? "text-yellow-400"
                        : "text-gray-300"
                    }
                  >
                    ★
                  </span>
                </button>
              ))}
            </div>

            <div className="mb-4">
              <label className="block text-gray-700 text-sm font-bold mb-2">
                Additional Comments
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full p-2 border rounded-lg focus:outline-none focus:border-purple-700"
                rows="4"
                placeholder="Tell us more about your experience..."
              />
            </div>

            <div className="flex justify-end space-x-2">
              <button
                onClick={onClose}
                className="px-4 py-2 text-gray-600 hover:text-gray-800"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmit}
                className="px-4 py-2 bg-purple-700 text-white rounded-lg hover:bg-purple-800"
              >
                Submit Feedback
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default Feedback;
