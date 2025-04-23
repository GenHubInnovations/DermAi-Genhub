import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { toast } from "react-toastify";

const BlogCreate = () => {
  const [formData, setFormData] = useState({
    title: "",
    content: "",
    image: null,
  });
  const [loading, setLoading] = useState(false);
  const [imagePreview, setImagePreview] = useState(null);
  const navigate = useNavigate();

  // Get user from localStorage
  const user = JSON.parse(localStorage.getItem("user") || "{}");
  const isAdmin = user && user.role === "admin";

  // Redirect if not admin
  useEffect(() => {
    if (!isAdmin) {
      toast.error("Only admins can access this page");
      navigate("/");
    }
  }, [isAdmin, navigate]);

  const handleChange = (e) => {
    if (e.target.name === "image") {
      const file = e.target.files[0];
      setFormData({
        ...formData,
        image: file,
      });

      // Create image preview
      if (file) {
        const reader = new FileReader();
        reader.onloadend = () => {
          setImagePreview(reader.result);
        };
        reader.readAsDataURL(file);
      } else {
        setImagePreview(null);
      }
    } else {
      setFormData({
        ...formData,
        [e.target.name]: e.target.value,
      });
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!formData.title.trim() || !formData.content.trim()) {
      toast.error("Title and content are required");
      return;
    }

    setLoading(true);

    try {
      // Prepare data for API
      let imageData = null;

      // Convert image to base64 if exists
      if (formData.image) {
        imageData = await convertToBase64(formData.image);
      }

      const postData = {
        title: formData.title,
        content: formData.content,
        author_id: user.id || "admin",
        author_name: user.name || "Admin",
        image_data: imageData,
      };

      const response = await axios.post(
        `${
          process.env.REACT_APP_API_URL || "http://localhost:5000"
        }/blog/posts`,
        postData
      );

      if (response.data.success) {
        toast.success("Blog post created successfully");
        navigate("/blog");
      } else {
        toast.error("Failed to create blog post");
      }
    } catch (error) {
      toast.error("Error creating blog post");
      console.error("Error creating blog post:", error);
    } finally {
      setLoading(false);
    }
  };

  // Convert file to base64
  const convertToBase64 = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.readAsDataURL(file);
      reader.onload = () => resolve(reader.result);
      reader.onerror = (error) => reject(error);
    });
  };

  if (!isAdmin) {
    return null; // Don't render anything while redirecting
  }

  return (
    <div className="min-h-[80vh] px-4 page-wrapper">
      <div className="w-full max-w-[90%] lg:max-w-[1200px] mx-auto">
        <h1 className="text-3xl font-bold text-center text-purple-700 mb-8">
          Create New Blog Post
        </h1>

        <form
          onSubmit={handleSubmit}
          className="bg-white rounded-xl shadow-lg overflow-hidden border border-gray-200 p-10"
        >
          <div className="mb-6">
            <label
              htmlFor="title"
              className="block text-gray-700 font-semibold mb-2"
            >
              Title
            </label>
            <input
              type="text"
              id="title"
              name="title"
              value={formData.title}
              onChange={handleChange}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500"
              placeholder="Enter blog title"
              required
            />
          </div>

          <div className="mb-6">
            <label
              htmlFor="content"
              className="block text-gray-700 font-semibold mb-2"
            >
              Content
            </label>
            <textarea
              id="content"
              name="content"
              value={formData.content}
              onChange={handleChange}
              rows="10"
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"
              placeholder="Write your blog content here..."
              required
            ></textarea>
          </div>

          <div className="mb-6">
            <label
              htmlFor="image"
              className="block text-gray-700 font-semibold mb-2"
            >
              Image (Optional)
            </label>
            <input
              type="file"
              id="image"
              name="image"
              onChange={handleChange}
              accept="image/*"
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"
            />

            {imagePreview && (
              <div className="mt-4">
                <p className="text-gray-700 font-semibold mb-2">
                  Image Preview:
                </p>
                <img
                  src={imagePreview}
                  alt="Preview"
                  className="max-w-full h-48 object-cover rounded-md"
                />
              </div>
            )}
          </div>

          <div className="flex justify-end">
            <button
              type="button"
              onClick={() => navigate("/blog")}
              className="px-6 py-2 mr-4 bg-gray-300 text-gray-700 rounded-md hover:bg-gray-400 transition"
              disabled={loading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-6 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition disabled:opacity-50"
              disabled={loading}
            >
              {loading ? "Creating..." : "Create Post"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default BlogCreate;
