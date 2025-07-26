// mcp-navigation.js
// This connects to your existing SSE infrastructure for MCP-driven navigation

class MCPNavigationListener {
    constructor() {
        // Update this URL if your Identity.API runs on different port
        this.identityUrl = 'https://localhost:5243';
        this.startListening();
        console.log('🤖 MCP navigation listener started');
    }

    startListening() {
        try {
            const eventSource = new EventSource(`${this.identityUrl}/api/sse/events`);
            
            // Listen for your existing navigate_to_checkout events
            eventSource.addEventListener('navigate_to_checkout', (event) => {
                try {
                    const data = JSON.parse(event.data);
                    console.log('Received checkout navigation event:', data);
                    
                    this.showNotification('🤖 MCP is opening checkout...');
                    
                    // Navigate to checkout page
                    setTimeout(() => {
                        window.location.href = '/cart';
                    }, 500);
                    
                } catch (error) {
                    console.warn('Error handling checkout navigation:', error);
                }
            });

            // Listen for cart updates too (your existing events)
            eventSource.addEventListener('item_added_to_cart', (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.showNotification(`🛒 Added ${data.productName || 'item'} to cart`);
                } catch (error) {
                    console.warn('Error handling cart update:', error);
                }
            });

            eventSource.onerror = (error) => {
                console.warn('SSE connection error - will retry automatically');
            };

            console.log('SSE connection established');
            
        } catch (error) {
            console.error('Failed to establish SSE connection:', error);
        }
    }

    showNotification(message) {
        // Simple notification that matches your eShop design
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #2196F3;
            color: white;
            padding: 15px 20px;
            border-radius: 5px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            z-index: 10000;
            font-family: Arial, sans-serif;
            max-width: 300px;
            animation: slideIn 0.3s ease-out;
        `;
        
        // Add simple animation
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
        `;
        document.head.appendChild(style);
        
        notification.innerHTML = `
            <div style="display: flex; align-items: center; gap: 10px;">
                <span>${message}</span>
            </div>
        `;
        
        document.body.appendChild(notification);

        // Remove notification after 3 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.style.animation = 'slideIn 0.3s ease-out reverse';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
                    }
                }, 300);
            }
        }, 3000);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('🔧 DEBUG: DOM loaded, starting listener...');
    console.log('🔧 DEBUG: Current URL:', window.location.href);
    console.log('✅ DEBUG: Starting MCP navigation listener (auth check disabled)...');
    new MCPNavigationListener();
});