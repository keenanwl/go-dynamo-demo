'use client'

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

interface User {
    id: string;
    email: string;
    name: string;
    // Add other user properties as needed
}

interface CardProps {
    children: React.ReactNode;
    className?: string;
}

interface UserCardProps {
    user: User;
}

const Card: React.FC<CardProps> = ({ children, className = '' }) => (
    <div className={`bg-white p-6 rounded-lg shadow-lg transition-all duration-300 hover:shadow-xl ${className}`}>
        {children}
    </div>
);

const UserCard: React.FC<UserCardProps> = ({ user }) => {
    const [isFlipped, setIsFlipped] = useState(false);

    return (
        <Card className="flex flex-col h-full transform hover:-translate-y-1 cursor-pointer">
            <div className={`flipper ${isFlipped ? 'flipped' : ''}`} onClick={() => setIsFlipped(!isFlipped)}>
                <div className="front">
                    <h3 className="text-xl font-semibold mb-2 text-indigo-600">{user.name}</h3>
                    <p className="text-sm text-gray-600 mb-4">{user.email}</p>
                    <div className="flex justify-between mt-auto">
                        <button className="bg-indigo-500 text-white px-4 py-2 rounded hover:bg-indigo-600 transition-colors duration-300">
                            View Profile
                        </button>
                        <button className="bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600 transition-colors duration-300">
                            Message
                        </button>
                    </div>
                </div>
                <div className="back">
                    <h3 className="text-xl font-semibold mb-2 text-indigo-600">User Details</h3>
                    <p className="text-sm text-gray-600 mb-2">ID: {user.id}</p>
                    <p className="text-sm text-gray-600 mb-4">Email: {user.email}</p>
                    <button className="w-full bg-purple-500 text-white px-4 py-2 rounded hover:bg-purple-600 transition-colors duration-300">
                        Edit User
                    </button>
                </div>
            </div>
        </Card>
    );
};

const Dashboard: React.FC = () => {
    const [users, setUsers] = useState<User[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState<boolean>(true);
    const router = useRouter();

    useEffect(() => {
        const fetchUsers = async () => {
            setIsLoading(true);
            setError(null);
            try {
                const response = await fetch('/api/users', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Use-Cookie-Auth': 'true',
                    },
                });

                if (response.status === 401) {
                    router.push('/');
                    return;
                }

                if (!response.ok) {
                    throw new Error('Failed to fetch users');
                }

                const userData = await response.json();
                setUsers(userData);
            } catch (error) {
                console.error('Error fetching users:', error);
                setError('Failed to load users. Please try again later.');
            } finally {
                setIsLoading(false);
            }
        };

        fetchUsers();
    }, [router]);

    if (isLoading) {
        return (
            <div className="p-4">
                <h1 className="text-2xl font-bold mb-4">Dashboard</h1>
                <p>Loading users...</p>
            </div>
        );
    }

    if (error) {
        return (
            <div className="p-4">
                <h1 className="text-2xl font-bold mb-4">Dashboard</h1>
                <p className="text-red-500">{error}</p>
            </div>
        );
    }

    return (
        <div className="p-4 bg-gray-100 min-h-screen">
            <h1 className="text-3xl font-bold mb-6 text-indigo-800">Dashboard</h1>
            <h2 className="text-2xl font-semibold mb-4 text-indigo-600">Users</h2>
            {(users || []).length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {users.map(user => (
                        <UserCard key={user.id} user={user} />
                    ))}
                </div>
            ) : (
                <p className="text-lg text-gray-600">No users found.</p>
            )}
        </div>
    );
}

export default Dashboard;