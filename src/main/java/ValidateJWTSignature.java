/*
  ~ Copyright (c) 2019  WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~ WSO2 Inc. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied. See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
*/

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Validate JWT Token signature using JWKS endpoint
 */
public class ValidateJWTSignature {

    private static final Logger logger = Logger.getLogger(ValidateJWTSignature.class.getName());
    private static final String JWT_TOKEN = "-jwttoken";
    private static final String JWKS_ENDPOINT = "-jwksEndponit";
    private static final Properties properties = new Properties();

    public static void main(String[] args) throws Exception {

        if (args.length > 0) {
            final List<String> argList = Arrays.asList(JWT_TOKEN, JWKS_ENDPOINT);

            int j = 0;
            for (int i = 0; i < args.length; ) {
                if (argList.contains(args[i]) && args.length > (i + 1)) {
                    properties.setProperty(argList.get(j), args[i + 1]);
                    i += 2;
                    j += 1;
                } else {
                    i += 1;
                }
            }
        }
        if (properties.size() != 2){
            logger.warning("Please provide the jwtToken and jwksEndpoint to proceed");
        } else {
            // sample JWT token <header>.<body>.<singnature>
            String signedJWTAsString = properties.getProperty(JWT_TOKEN);
            // JWKs Endpoint
            String jwksEndpoint = properties.getProperty(JWKS_ENDPOINT);

            decodeJWTToken(signedJWTAsString);

            validateSignature(signedJWTAsString, jwksEndpoint);
        }
    }

    /**
     * Validate the signature in JWT token
     * @param jwksEndpoint
     * @param signedJWTAsString
     * @throws ParseException
     * @throws JOSEException
     */
    private static void validateSignature(String signedJWTAsString, String jwksEndpoint) throws ParseException,
            JOSEException, net.minidev.json.parser.ParseException {

        // To disable SSL.
        disableSslVerification();

        String responseStr = sendRequest(jwksEndpoint);

        //create a json object
        JSONObject jsonObject = (JSONObject)new JSONParser().parse(responseStr);

        //Retrieve Key and assigned to JSONArray
        JSONArray jwksKeyArray = (JSONArray) jsonObject.get("keys");

        //Retrieve the first value
        JSONObject jwksKeys = (JSONObject) jwksKeyArray.get(0);

        String modulusString = (String)jwksKeys.get("n");
        String exponentString = (String)jwksKeys.get("e");

        //Decoded modulus,exponent
        BigInteger modulus = new Base64(modulusString).decodeToBigInteger();
        BigInteger exponent = new Base64(exponentString).decodeToBigInteger();

        //invoke getPublicKey() and retrieve public key using modulus and exponent
        RSAPublicKey publicKey =  (RSAPublicKey)getPublicKey(modulus, exponent);

        SignedJWT signedJWT = SignedJWT.parse(signedJWTAsString);

        JWSVerifier verifier = new RSASSAVerifier(publicKey);

        if (signedJWT.verify(verifier)) {
            logger.info("Signature is Valid");
        } else {
            logger.info("Signature is NOT Valid");
        }
    }

    /**
     * Get a public key
     * @param modulus
     * @param publicExponent
     * @return
     */
    private static PublicKey getPublicKey(BigInteger modulus, BigInteger publicExponent) {

        try {
            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = factory.generatePublic(spec);

            return publicKey;
        }
        catch( Exception e ) {
            System.out.println(e.toString());
        }
        return null;
    }

    /**
     * Decode the JWT token and print the claims
     * @param encodedJWTToken
     * @return
     */
    private static void decodeJWTToken(String encodedJWTToken) throws ParseException {

        SignedJWT signedJWT = SignedJWT.parse(encodedJWTToken);
        String output = "JWTToken Claims: \n";
        for(Map.Entry<String,Object> claim : signedJWT.getJWTClaimsSet().getClaims().entrySet()) {
            output += "    "+claim.getKey() +" : "+claim.getValue()+"\n";
        }
        logger.info(output);
    }

    /**
     * Send a request to jwksEndpoint.
     * @param jwksEndpoint
     * @return jwksResponse
     */
    private static String sendRequest(String jwksEndpoint){
        String https_url = jwksEndpoint;
        URL url;
        try {

            url = new URL(https_url);
            HttpsURLConnection con = (HttpsURLConnection)url.openConnection();
            return getValueFromJWKSEndpoint(con);

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;

    }

    /**
     * Get the signature validation details from the jwksEndpoint.
     * @param con
     * @return jwksResponse
     */
    private static String getValueFromJWKSEndpoint(HttpsURLConnection con){
        String jwksResponse = "";
        if(con!=null){

            try {
                BufferedReader br =
                        new BufferedReader(
                                new InputStreamReader(con.getInputStream()));

                String input;

                while ((input = br.readLine()) != null){
                    jwksResponse += input;
                }
                br.close();

            } catch (IOException e) {
                e.printStackTrace();
            }

        }
        return jwksResponse;

    }

    /**
     * disable SSL.
     */
    private static void disableSslVerification() {
        try {
            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }

                        public void checkClientTrusted(X509Certificate[] certs,
                                                       String authType) {
                        }

                        public void checkServerTrusted(X509Certificate[] certs,
                                                       String authType) {
                        }
                    } };

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };

            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
    }


}
