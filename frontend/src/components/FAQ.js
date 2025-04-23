import React, { useState } from "react";
import { motion } from "framer-motion";

function FAQ() {
  const [activeIndex, setActiveIndex] = useState(null);

  const faqs = [
    {
      question: "What is DermAI Assistant?",
      answer:
        "DermAI Assistant is an AI-powered tool that helps detect and analyze skin conditions. It uses advanced machine learning algorithms to provide instant analysis of skin images, offering preliminary insights about potential skin conditions.",
    },
    {
      question: "How accurate is the skin disease detection?",
      answer:
        "Our AI model has been trained on a large dataset of dermatological images and achieves high accuracy in detecting common skin conditions. However, it's important to note that this tool is designed to provide preliminary information and should not replace professional medical advice from a dermatologist.",
    },
    {
      question: "What types of skin conditions can DermAI detect?",
      answer:
        "DermAI can detect various skin conditions including autoimmune and inflammatory dermatoses, bullous diseases, infectious dermatoses, inflammatory dermatoses, neoplastic lesions, and pigmentation, hair, and nail disorders. Each category includes multiple subconditions.",
    },
    {
      question: "How do I use the skin analysis feature?",
      answer:
        "To use the skin analysis feature, navigate to the 'Predict' page, fill in your patient information, upload a clear image of the skin condition, and click 'Analyze Image'. The system will process the image and provide you with a detailed analysis and recommendations.",
    },
    {
      question: "Is my data secure and private?",
      answer:
        "Yes, we take data privacy seriously. All images and personal information are encrypted and stored securely. We do not share your data with third parties without your consent. For more details, please review our Privacy Policy.",
    },
    {
      question: "Can I save my analysis history?",
      answer:
        "Yes, if you create an account and log in, you can save your analysis history. This allows you to track changes over time and compare results from different analyses.",
    },
    {
      question: "What should I do after receiving my analysis?",
      answer:
        "After receiving your analysis, we recommend consulting with a healthcare professional, particularly a dermatologist, for a proper diagnosis and treatment plan. Our analysis is meant to provide preliminary information and should not be used as a substitute for professional medical advice.",
    },
    {
      question:
        "How can I get more detailed information about a specific skin condition?",
      answer:
        "Our blog section contains detailed articles about various skin conditions, their symptoms, and treatment options. You can also use our chatbot feature to ask specific questions about skin conditions.",
    },
    {
      question: "Can I use DermAI Assistant on my mobile device?",
      answer:
        "Yes, DermAI Assistant is fully responsive and works on mobile devices. You can upload images directly from your phone's camera or gallery for analysis.",
    },
    {
      question: "How can I provide feedback about the analysis?",
      answer:
        "After each analysis, you have the option to provide feedback on the accuracy and helpfulness of the results. This helps us improve our system. Additionally, you can contact us directly through the Contact Us page with any suggestions or concerns.",
    },
  ];

  const toggleAccordion = (index) => {
    setActiveIndex(activeIndex === index ? null : index);
  };

  return (
    <div className="min-h-[80vh] bg-gradient-to-r from-blue-50 to-purple-50 p-6">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="max-w-4xl mx-auto bg-white rounded-xl shadow-xl p-8 mt-16 lg:mt-16"
      >
        <h1 className="text-3xl font-bold text-purple-700 text-center mb-8">
          Frequently Asked Questions
        </h1>
        <p className="text-gray-600 text-center mb-8">
          Find answers to common questions about DermAI Assistant and skin
          disease detection.
        </p>

        <div className="space-y-4">
          {faqs.map((faq, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="border border-gray-200 rounded-lg overflow-hidden"
            >
              <button
                className="w-full text-left px-6 py-4 flex justify-between items-center bg-white hover:bg-purple-50 transition-colors duration-200"
                onClick={() => toggleAccordion(index)}
              >
                <span className="font-semibold text-purple-700">
                  {faq.question}
                </span>
                <svg
                  className={`w-5 h-5 text-purple-700 transform transition-transform duration-200 ${
                    activeIndex === index ? "rotate-180" : ""
                  }`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M19 9l-7 7-7-7"
                  />
                </svg>
              </button>
              <div
                className={`px-6 overflow-hidden transition-all duration-300 ${
                  activeIndex === index ? "max-h-96 py-4" : "max-h-0"
                }`}
              >
                <p className="text-gray-600">{faq.answer}</p>
              </div>
            </motion.div>
          ))}
        </div>

        <div className="mt-8 text-center">
          <p className="text-gray-600">
            Still have questions?{" "}
            <a
              href="/contact"
              className="text-purple-700 font-semibold hover:underline"
            >
              Contact us
            </a>{" "}
            for more information.
          </p>
        </div>
      </motion.div>
    </div>
  );
}

export default FAQ;
