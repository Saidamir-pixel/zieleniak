# mode_project

Project Topic

This web application provides an online vegetable store where customers can schedule their grocery orders for a chosen pickup date. It includes a “GreenPoint” feature that grants 2 points for every 1 złoty spent, which can be redeemed for discounts or selected items. The system encourages flexible and sustainable shopping habits while rewarding loyal customers.

Contributor

    SAIDAMIR NAVRUZOV, Student #44476

Key Features

    Scheduled Purchases: Users can select a specific date for order assembly.
    GreenPoint System: Earn 2 GreenPoints for each 1 złoty spent, redeemable for discounts or items.
    User-Friendly Interface: Simple navigation for browsing products, adding to cart, and checkout.


Additional Notes

    Database: Uses MySQL in a Docker container (check docker-compose.yml for credentials).
    GreenPoints: Accumulate automatically and can be redeemed at checkout or for specific reward items.

## How to Run (Docker Compose)

1. Clone or download this repository.
2. In the project root folder (where `docker-compose.yml` is located), run:

   docker-compose down
   docker-compose up -d --build

Open http://localhost:8080 in your browser to access the app.
