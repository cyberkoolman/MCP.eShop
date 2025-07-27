// mcp-navigation.js
// This connects to your existing SSE infrastructure for MCP-driven navigation

class MCPNavigationListener {
    constructor() {
        // Update this URL if your Identity.API runs on different port
        this.identityUrl = 'https://localhost:5243';
        this.startListening();
        console.log('MCP navigation listener started');
    }

    startListening() {
        try {
            const eventSource = new EventSource(`${this.identityUrl}/api/sse/events`);
            
            // Listen for your existing navigate_to_checkout events
            eventSource.addEventListener('navigate_to_checkout', (event) => {
                try {
                    const data = JSON.parse(event.data);
                    console.log('Received checkout navigation event:', data);
                    
                    this.showNotification('MCP is opening checkout...');
                    
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
                    this.showNotification(`Added ${data.productName || 'item'} to cart`);
                } catch (error) {
                    console.warn('Error handling cart update:', error);
                }
            });

            // FIXED: Silent cart addition event handler
            eventSource.addEventListener('add_item_to_cart', async (event) => {
                try {
                    const data = JSON.parse(event.data);
                    console.log('Received MCP silent cart add request:', data);
                    
                    const productId = data.Data?.productId || data.productId;
                    const quantity = data.Data?.quantity || data.quantity || 1;
                    
                    console.log(`Silently adding product ${productId} to cart (quantity: ${quantity})`);
                    
                    // Make background API call to add item to cart - FIXED: Added this.
                    const success = await this.addToCartSilently(productId, quantity);
                    
                    if (success) {
                        this.showNotification(`Added item to cart silently`);
                    } else {
                        this.showNotification(`Failed to add item to cart`);
                    }
                    
                } catch (error) {
                    console.warn('Error handling silent cart add request:', error);
                    this.showNotification(`Error adding item to cart`);
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

    // REPLACE the addToCartSilently method in your MCPNavigationListener class with this:
    async addToCartSilently(productId, quantity = 1) {
        try {
            // First, navigate to the product page to get the form and CSRF token
            console.log(`Fetching product page for CSRF token: /item/${productId}`);
            
            const pageResponse = await fetch(`/item/${productId}`, {
                method: 'GET',
                credentials: 'same-origin'
            });
            
            if (!pageResponse.ok) {
                console.warn(`Failed to fetch product page: ${pageResponse.status}`);
                return false;
            }
            
            const pageHtml = await pageResponse.text();
            
            // Extract CSRF token from the HTML
            const tokenMatch = pageHtml.match(/name="__RequestVerificationToken"[^>]*value="([^"]+)"/);
            
            if (!tokenMatch) {
                console.warn('Could not find CSRF token in product page');
                return false;
            }
            
            const csrfToken = tokenMatch[1];
            console.log(`Found CSRF token: ${csrfToken.substring(0, 20)}...`);
            
            // Use the exact form data format from the real form
            const formData = new URLSearchParams({
                '_handler': 'add-to-cart',  // FIXED: Use _handler with underscore!
                '__RequestVerificationToken': csrfToken
            });
            
            console.log(`Posting to /item/${productId} with correct form data (_handler)`);
            
            const response = await fetch(`/item/${productId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: formData,
                credentials: 'same-origin'
            });
            
            if (response.ok) {
                console.log(`Successfully added product ${productId} to cart!`);
                return true;
            } else {
                const responseText = await response.text();
                console.warn(`Form-based add failed with status: ${response.status}`);
                console.warn(`Response: ${responseText.substring(0, 200)}...`);
                
                // Still try the basket API as fallback
                return await this.tryBasketApi(productId, quantity);
            }
            
        } catch (error) {
            console.warn('Error with form-based cart addition:', error);
            return await this.tryBasketApi(productId, quantity);
        }
    }

    // FIXED: Basket API fallback method
    async tryBasketApi(productId, quantity = 1) {
        try {
            // This assumes the basket API is available - adjust URL as needed
            const response = await fetch('/api/v1/basket/items', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    productId: productId,
                    quantity: quantity
                }),
                credentials: 'same-origin'
            });
            
            if (response.ok) {
                console.log(`Successfully added product ${productId} via Basket API`);
                return true;
            } else {
                console.warn(`Basket API add failed with status: ${response.status}`);
                return false;
            }
            
        } catch (error) {
            console.warn('Error with Basket API cart addition:', error);
            return false;
        }
    }
    
    // FIXED: Notification method (already correct)
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
    console.log('DEBUG: DOM loaded, starting listener...');
    console.log('DEBUG: Current URL:', window.location.href);
    console.log('DEBUG: Starting MCP navigation listener (auth check disabled)...');
    new MCPNavigationListener();
});