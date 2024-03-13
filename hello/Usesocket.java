package hello;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URL;


public class Usesocket {

    public static int sendRequest(String urlString) {
        try {
            // Parse URL to get host and path
            URL url = new URL(urlString);
            String host = url.getHost();
            String path = url.getPath();

            // Determine port based on the scheme (80 for HTTP, 443 for HTTPS)
            int port = (url.getProtocol().equalsIgnoreCase("https")) ? 443 : 80;

            // Create socket connection
            Socket socket = new Socket(host, port);

            // Formulate HTTP request
            String request = "GET " + path + " HTTP/1.1\r\n";
            request += "Host: " + host + "\r\n";
            request += "Connection: close\r\n\r\n";

            // Send request
            OutputStream outputStream = socket.getOutputStream();
            outputStream.write(request.getBytes());
            outputStream.flush();

            // Read response
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String line;
            StringBuilder response = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                response.append(line).append("\n");
            }

            // Close resources
            reader.close();
            outputStream.close();
            socket.close();

            // Parse and return status code
            String[] responseLines = response.toString().split("\n");
            String[] statusLine = responseLines[0].split(" ");
            return Integer.parseInt(statusLine[1]);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return -1; // Return -1 if request fails
    }

    public static void main(String[] args) {
        String url = "https://www.example.com";
        int statusCode = sendRequest(url);
        System.out.println("Status code: " + statusCode);
    }
}
