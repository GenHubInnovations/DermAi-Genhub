import React, { useState, useEffect } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import axios from "axios";
import { toast } from "react-toastify";

const BlogEdit = () => {
  const [formData, setFormData] = useState({
    title: "",
    content: "",
    image: null,
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [imagePreview, setImagePreview] = useState(null);
  const { id } = useParams();
  const navigate = useNavigate();

  // Get user from localStorage
  const user = JSON.parse(localStorage.getItem("user") || "{}");
  const isAdmin = user && user.role === "admin";

  // Fetch post data when component mounts
  useEffect(() => {
    if (!isAdmin) {
      toast.error("Only admins can access this page");
      navigate("/");
      return;
    }

    // Define fetchPost inside useEffect to avoid dependency issues
    const fetchPost = async () => {
      try {
        setLoading(true);
        const response = await axios.get(
          `${
            process.env.REACT_APP_API_URL || "http://localhost:5000"
          }/blog/posts/${id}`
        );

        if (response.data.success) {
          const post = response.data.post;
          setFormData({
            title: post.title,
            content: post.content,
            image: null,
          });

          // Set image preview if exists
          if (post.image_data) {
            setImagePreview(post.image_data);
          }
        } else {
          toast.error("Failed to fetch blog post");
          navigate("/blog");
        }
      } catch (error) {
        toast.error("Error fetching blog post");
        console.error("Error fetching blog post:", error);
        navigate("/blog");
      } finally {
        setLoading(false);
      }
    };

    fetchPost();
  }, [id, isAdmin, navigate]);

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

    setSaving(true);

    try {
      // Prepare data for API
      const updateData = {
        title: formData.title,
        content: formData.content,
      };

      // Convert image to base64 if a new one was uploaded
      if (formData.image) {
        updateData.image_data = await convertToBase64(formData.image);
      }

      const response = await axios.put(
        `${
          process.env.REACT_APP_API_URL || "http://localhost:5000"
        }/blog/posts/${id}`,
        updateData
      );

      if (response.data.success) {
        toast.success("Blog post updated successfully");
        navigate(`/blog/${id}`);
      } else {
        toast.error("Failed to update blog post");
      }
    } catch (error) {
      toast.error("Error updating blog post");
      console.error("Error updating blog post:", error);
    } finally {
      setSaving(false);
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

  if (loading) {
    return (
      <div className="min-h-[50vh] flex justify-center items-center page-wrapper">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-purple-500"></div>
      </div>
    );
  }

  if (!formData.title) {
    return (
      <div className="min-h-[80vh] px-4 w-full max-w-[90%] lg:max-w-[1400px] mx-auto page-wrapper text-center">
        <h1 className="text-3xl font-bold text-gray-800 mb-4">
          Post Not Found
        </h1>
        <p className="mb-6">
          The blog post you're trying to edit doesn't exist or has been removed.
        </p>
        <Link
          to="/blog"
          className="inline-block bg-purple-600 text-white px-6 py-3 rounded-lg hover:bg-purple-700 transition duration-300"
        >
          Back to Blog
        </Link>
      </div>
    );
  }

  return (
    <div className="min-h-[80vh] px-4 page-wrapper">
      <div className="w-full max-w-[90%] lg:max-w-[1200px] mx-auto">
        <h1 className="text-3xl font-bold text-center text-purple-700 mb-8">
          Edit Blog Post
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
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"
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
              onClick={() => navigate(`/blog/${id}`)}
              className="px-6 py-2 mr-4 bg-gray-300 text-gray-700 rounded-md hover:bg-gray-400 transition"
              disabled={saving}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-6 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition disabled:opacity-50"
              disabled={saving}
            >
              {saving ? "Saving..." : "Save Changes"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default BlogEdit;
