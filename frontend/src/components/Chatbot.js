import React, { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, Send, MessageCircle, Trash2 } from "lucide-react";
import { GoogleGenerativeAI } from "@google/generative-ai";
import ReactMarkdown from "react-markdown";
import knowledgeBase from "../lib/data"; // Import the knowledge base

// Function to load knowledge file
const loadKnowledgeBase = async () => {
  return knowledgeBase; // Return the knowledge base directly
};

function Chatbot() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const chatContainerRef = useRef(null);
  const genAI = new GoogleGenerativeAI(process.env.REACT_APP_GEMINI_API_KEY);

  useEffect(() => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop =
        chatContainerRef.current.scrollHeight;
    }
  }, [messages]);

  const handleSendMessage = async () => {
    if (!inputMessage.trim()) return;

    const userMessage = {
      text: inputMessage,
      sender: "user",
      timestamp: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInputMessage("");
    setIsLoading(true);

    try {
      const knowledgeBaseText = await loadKnowledgeBase();

      // Create a prompt that includes the knowledge base
      const prompt = `Here is the knowledge base: "${knowledgeBaseText}". Based on this information, answer the following question: ${inputMessage}`;

      const model = genAI.getGenerativeModel({
        model: "gemini-1.5-pro-latest",
      });

      const result = await model.generateContent(prompt);
      const response = await result.response;

      const botMessage = {
        text: response.text(), // Use the response from the model
        sender: "bot",
        timestamp: new Date().toLocaleTimeString(),
      };

      setMessages((prev) => [...prev, botMessage]);
    } catch (error) {
      console.error("Error getting response:", error);
      const errorMessage = {
        text: "Sorry, I couldn't process your request. Please try again.",
        sender: "bot",
        timestamp: new Date().toLocaleTimeString(),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const clearChat = () => {
    setMessages([]);
  };

  return (
    <>
      {/* Floating Chat Button */}
      <motion.button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 w-14 h-14 rounded-full bg-purple-700 text-white shadow-lg hover:bg-purple-800 transition-colors flex items-center justify-center"
        whileHover={{ scale: 1.1 }}
        whileTap={{ scale: 0.9 }}
      >
        <MessageCircle size={24} />
      </motion.button>

      {/* Chat Popup */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            className="fixed bottom-24 right-6 w-96 h-[500px] bg-white rounded-lg shadow-xl flex flex-col"
          >
            {/* Chat Header */}
            <div className="p-4 bg-purple-700 text-white rounded-t-lg flex justify-between items-center">
              <h3 className="font-semibold">DermAI Chat Assistant</h3>
              <div className="flex gap-2">
                <button
                  onClick={clearChat}
                  className="p-1 hover:bg-purple-600 rounded"
                  title="Clear chat"
                >
                  <Trash2 size={20} />
                </button>
                <button
                  onClick={() => setIsOpen(false)}
                  className="p-1 hover:bg-purple-600 rounded"
                >
                  <X size={20} />
                </button>
              </div>
            </div>

            {/* Chat Messages */}
            <div
              ref={chatContainerRef}
              className="flex-1 overflow-y-auto p-4 space-y-4"
            >
              {messages.map((message, index) => (
                <div
                  key={index}
                  className={`flex ${
                    message.sender === "user" ? "justify-end" : "justify-start"
                  }`}
                >
                  <div
                    className={`max-w-[80%] rounded-lg p-3 ${
                      message.sender === "user"
                        ? "bg-purple-700 text-white"
                        : "bg-gray-100 text-gray-800"
                    }`}
                  >
                    <div className="prose prose-sm max-w-none dark:prose-invert">
                      <ReactMarkdown
                        components={{
                          p: ({ children }) => (
                            <p
                              className={`text-sm mb-2 ${
                                message.sender === "user"
                                  ? "text-white"
                                  : "text-gray-900"
                              }`}
                            >
                              {children}
                            </p>
                          ),
                          strong: ({ children }) => (
                            <strong
                              className={`font-bold ${
                                message.sender === "user"
                                  ? "text-white"
                                  : "text-gray-900"
                              }`}
                            >
                              {children}
                            </strong>
                          ),
                          em: ({ children }) => (
                            <em
                              className={`italic ${
                                message.sender === "user"
                                  ? "text-white"
                                  : "text-gray-900"
                              }`}
                            >
                              {children}
                            </em>
                          ),
                          ul: ({ children }) => (
                            <ul
                              className={`list-disc pl-4 mb-2 ${
                                message.sender === "user"
                                  ? "text-white"
                                  : "text-gray-900"
                              }`}
                            >
                              {children}
                            </ul>
                          ),
                          ol: ({ children }) => (
                            <ol
                              className={`list-decimal pl-4 mb-2 ${
                                message.sender === "user"
                                  ? "text-white"
                                  : "text-gray-900"
                              }`}
                            >
                              {children}
                            </ol>
                          ),
                          li: ({ children }) => (
                            <li
                              className={`mb-1 ${
                                message.sender === "user"
                                  ? "text-white"
                                  : "text-gray-900"
                              }`}
                            >
                              {children}
                            </li>
                          ),
                          h1: ({ children }) => (
                            <h1
                              className={`text-xl font-bold mb-2 ${
                                message.sender === "user"
                                  ? "text-white"
                                  : "text-gray-900"
                              }`}
                            >
                              {children}
                            </h1>
                          ),
                          h2: ({ children }) => (
                            <h2
                              className={`text-lg font-bold mb-2 ${
                                message.sender === "user"
                                  ? "text-white"
                                  : "text-gray-900"
                              }`}
                            >
                              {children}
                            </h2>
                          ),
                          h3: ({ children }) => (
                            <h3
                              className={`text-base font-bold mb-2 ${
                                message.sender === "user"
                                  ? "text-white"
                                  : "text-gray-900"
                              }`}
                            >
                              {children}
                            </h3>
                          ),
                          code: ({ children }) => (
                            <code
                              className={`bg-gray-200 dark:bg-gray-700 rounded px-1 ${
                                message.sender === "user"
                                  ? "text-white"
                                  : "text-gray-900"
                              }`}
                            >
                              {children}
                            </code>
                          ),
                          pre: ({ children }) => (
                            <pre
                              className={`bg-gray-200 dark:bg-gray-700 rounded p-2 mb-2 overflow-x-auto ${
                                message.sender === "user"
                                  ? "text-white"
                                  : "text-gray-900"
                              }`}
                            >
                              {children}
                            </pre>
                          ),
                        }}
                      >
                        {message.text}
                      </ReactMarkdown>
                    </div>
                    <span className="text-xs opacity-75 mt-1 block">
                      {message.timestamp}
                    </span>
                  </div>
                </div>
              ))}
              {isLoading && (
                <div className="flex justify-start">
                  <div className="bg-gray-100 rounded-lg p-3">
                    <div className="flex space-x-2">
                      <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" />
                      <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce delay-100" />
                      <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce delay-200" />
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Chat Input */}
            <div className="p-4 border-t">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                  onKeyPress={(e) => e.key === "Enter" && handleSendMessage()}
                  placeholder="Type your message..."
                  className="flex-1 p-2 border rounded-lg focus:outline-none focus:border-purple-700"
                />
                <button
                  onClick={handleSendMessage}
                  disabled={isLoading || !inputMessage.trim()}
                  className={`p-2 rounded-lg ${
                    isLoading || !inputMessage.trim()
                      ? "bg-gray-300 cursor-not-allowed"
                      : "bg-purple-700 text-white hover:bg-purple-800"
                  }`}
                >
                  <Send size={20} />
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}

export default Chatbot;
