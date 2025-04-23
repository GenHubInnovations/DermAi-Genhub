import React from "react";
import { motion } from "framer-motion";

const PrivacyPolicy = () => {
  return (
    <div className="bg-gradient-to-r from-purple-50 to-emerald-50 page-wrapper">
      <motion.section
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.6 }}
        className="text-center py-16 px-4"
      >
        <h1 className="text-4xl md:text-5xl font-bold text-purple-700 mb-6">
          Privacy Policy
        </h1>
        <p className="text-xl text-gray-600 max-w-3xl mx-auto mb-6">
          At DermAI, we are committed to protecting your privacy. This policy
          outlines how we handle your personal information.
        </p>
      </motion.section>

      <div className="max-w-7xl mx-auto px-4">
        <h2 className="text-3xl font-bold text-purple-700 mb-4">
          Information We Collect
        </h2>
        <ul className="list-disc pl-6 mb-6">
          <li>Personal identification information (name, email, etc.)</li>
          <li>Health-related information (skin conditions, images, etc.)</li>
          <li>Usage data (how you interact with our services)</li>
        </ul>

        <h2 className="text-3xl font-bold text-purple-700 mb-4">
          How We Use Your Information
        </h2>
        <ul className="list-disc pl-6 mb-6">
          <li>To provide and maintain our services</li>
          <li>To improve our services based on user feedback</li>
          <li>To communicate with you regarding your account and services</li>
        </ul>

        <h2 className="text-3xl font-bold text-purple-700 mb-4">Your Rights</h2>
        <ul className="list-disc pl-6 mb-6">
          <li>You have the right to access your personal information.</li>
          <li>You can request corrections to your information.</li>
          <li>You can request the deletion of your data.</li>
        </ul>

        <h2 className="text-3xl font-bold text-purple-700 mb-4">
          Changes to This Policy
        </h2>
        <p className="text-gray-600 mb-6">
          We may update our privacy policy from time to time. We will notify you
          of any changes by posting the new policy on this page.
        </p>
      </div>
    </div>
  );
};

export default PrivacyPolicy;
