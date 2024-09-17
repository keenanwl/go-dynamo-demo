import axios, { AxiosResponse } from 'axios';

// Define the base URL for the API
const API_BASE_URL = '/api';

// Define the User interface
interface User {
    id?: string;
    name: string;
    email: string;
    // Add other user properties as needed
}

interface LoginCredentials {
    email: string;
    password: string;
}

interface LoginResponse {
    token: string;
}

// Create an axios instance
const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

// User service object
const userService = {

    // Login user
    login: async (credentials: LoginCredentials): Promise<LoginResponse> => {
        try {
            const response: AxiosResponse<LoginResponse> = await api.post('/login', credentials);
            return response.data;
        } catch (error) {
            console.error('Error logging in:', error);
            throw error;
        }
    },

    // Create a new user
    createUser: async (userData: Omit<User, 'id'>): Promise<User> => {
        try {
            const response: AxiosResponse<User> = await api.post('/users', userData);
            return response.data;
        } catch (error) {
            console.error('Error creating user:', error);
            throw error;
        }
    },

    // Get a user by ID
    getUser: async (id: string): Promise<User> => {
        try {
            const response: AxiosResponse<User> = await api.get(`/users/${id}`);
            return response.data;
        } catch (error) {
            console.error(`Error getting user with id ${id}:`, error);
            throw error;
        }
    },

    // Get a user by ID
    getUsers: async (): Promise<User> => {
        try {
            const response: AxiosResponse<User> = await api.get(`/users`);
            return response.data;
        } catch (error) {
            console.error(`Error getting users:`, error);
            throw error;
        }
    },

    // Update a user
    updateUser: async (id: string, userData: Partial<User>): Promise<User> => {
        try {
            const response: AxiosResponse<User> = await api.put(`/users/${id}`, userData);
            return response.data;
        } catch (error) {
            console.error(`Error updating user with id ${id}:`, error);
            throw error;
        }
    },

    // Delete a user
    deleteUser: async (id: string): Promise<void> => {
        try {
            await api.delete(`/users/${id}`);
        } catch (error) {
            console.error(`Error deleting user with id ${id}:`, error);
            throw error;
        }
    },
};

export default userService;