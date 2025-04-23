import React from "react";
import { Link } from "react-router-dom";

function Footer() {
  return (
    <footer className="w-full bg-purple-950 text-white py-12">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div>
            <h3 className="text-xl font-bold mb-4">DermAI Assistant</h3>
            <p className="text-purple-100">
              Advanced skin disease detection powered by artificial
              intelligence.
            </p>
          </div>
          <div>
            <h4 className="text-lg font-semibold mb-4">Quick Links</h4>
            <ul className="space-y-2">
              <li>
                <Link to="/" className="text-purple-100 hover:text-white">
                  Home
                </Link>
              </li>
              <li>
                <Link
                  to="/predict"
                  className="text-purple-100 hover:text-white"
                >
                  Diagnose
                </Link>
              </li>
              <li>
                <Link to="/about" className="text-purple-100 hover:text-white">
                  About
                </Link>
              </li>
            </ul>
          </div>
          <div>
            <h4 className="text-lg font-semibold mb-4">Resources</h4>
            <ul className="space-y-2">
              <li>
                <Link to="/blog" className="text-purple-100 hover:text-white">
                  Blog
                </Link>
              </li>
              <li>
                <Link to="/faq" className="text-purple-100 hover:text-white">
                  FAQs
                </Link>
              </li>
              <li>
                <Link
                  to="/support"
                  className="text-purple-100 hover:text-white"
                >
                  Support
                </Link>
              </li>
            </ul>
          </div>
          <div>
            <h4 className="text-lg font-semibold mb-4">Contact</h4>
            <ul className="space-y-2">
              <li className="text-purple-100">
                Email: contact@genhubInnovation.com
              </li>
              <li className="text-purple-100">
                <div className="text-purple-100 flex gap-2">
                  <div>Phone:</div>
                  <div className="flex flex-col">
                    <div>+91 6385499454</div>
                    <div>+91 6385282033</div>
                  </div>
                </div>
              </li>
            </ul>
          </div>
        </div>
        <div className="border-t border-purple-600 mt-8 pt-8 flex flex-col md:flex-row justify-between text-center">
          <p className="text-purple-100 mb-2 md:mb-0">
            &copy; 2025 DermAI Assistant - All Rights Reserved.
          </p>
          <div className="flex flex-col md:flex-row justify-center items-center">
            {/* Privacy Policy */}
            <Link to="/privacy-policy" className=" mt-4 md:mt-0 md:ml-4">
              Privacy Policy
            </Link>
          </div>
          <p className="text-purple-100">
            Designed and Developed by{" "}
            <span className="">
              <a href="https://genhubinnovations.com">GenHub Innovations</a>
            </span>
            .
          </p>
        </div>
      </div>
    </footer>
  );
}

export default Footer;
