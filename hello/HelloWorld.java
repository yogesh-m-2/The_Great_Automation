package hello;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ConnectException;
import hello.Usesocket;

class RequestThread extends Thread {
    private String url;

    public RequestThread(String url) {
        this.url = url;
    }

    public void run() {
        HttpURLConnection connection = null;
        try {
            Usesocket s = new Usesocket();
            URL urlObj = new URL(url);
            connection = (s) urlObj.openConnection();
            connection.setRequestMethod("GET");
            int timeoutInMillis = 5000;
            connection.setConnectTimeout(timeoutInMillis);
            connection.setReadTimeout(timeoutInMillis);

            int responseCode = connection.getResponseCode();
            if(responseCode!=404){
                System.out.println("Response from " + url + ": " + responseCode);
            }
            

            // BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            // String inputLine;
            // StringBuffer response = new StringBuffer();

            // while ((inputLine = in.readLine()) != null) {
            //     response.append(inputLine);
            // }
            // in.close();

            // System.out.println("Response from " + url + ": " + response.toString());
            
        }catch (ConnectException e) {
            System.out.println("no connection for  " + url);
        }catch (FileNotFoundException e) {
            // System.out.println("");
        }catch (Exception e) {
            // System.out.println("");
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}

public class HelloWorld {
    /**
     * @param args
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {
        String baseUrl = "https://beta.unifytwin.com";
        int numUrls = 15000;
        RequestThread[] threads = new RequestThread[numUrls]; // Create an array to hold all threads
        HttpURLConnection connection = null;
        String wordlisturl = "https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt";
        URL urlObj = new URL(wordlisturl);
        connection = (HttpURLConnection) urlObj.openConnection();
        connection.setRequestMethod("GET");
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        ArrayList<String> response = new ArrayList<>();
        while ((inputLine = in.readLine()) != null) {
            response.add(inputLine);
        }
        in.close();
        int count = 0;
        System.out.println(threads.length);
        for (String line : response) {
            String url = baseUrl +"/"+ line; // Adjust index to start from 1
            threads[count] = new RequestThread(url);
            count+=1;
        }
      
        

        for (int i = 0; i < numUrls; i++) {
            threads[i].start();
            // System.out.println(count);
        }
    }
}

