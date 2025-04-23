import axios from 'axios';

// Clean up URL to avoid double slashes
const baseURL = process.env.REACT_APP_API_URL 
  ? process.env.REACT_APP_API_URL.replace(/\/$/, '')
  : 'http://localhost:5000';

const api = axios.create({
  baseURL,
  withCredentials: true
});

export default api; 