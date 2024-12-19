document.addEventListener("DOMContentLoaded", () => {
    // Attach event listener to the button
    const authorizeButton = document.getElementById("authorize");
    if (authorizeButton) {
        authorizeButton.addEventListener("click", authorizeWithFitbit);
    }

    // Handle redirect after Fitbit authorization
    if (window.location.search.includes("code=")) {
        handleAuthorizationResponse();
    }
});

// Configuration
const CLIENT_ID = "23PZMC"; // Replace with your Fitbit client ID
const REDIRECT_URI = "https://nicholas888444.github.io/fitbitapi/index.html"; // Replace with your redirect URI

// Generate a random code verifier
function generateCodeVerifier() {
    const array = new Uint8Array(64);
    window.crypto.getRandomValues(array);
    return btoa(String.fromCharCode.apply(null, array))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// Generate a code challenge from the verifier
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await window.crypto.subtle.digest("SHA-256", data);
    return btoa(String.fromCharCode.apply(null, new Uint8Array(digest)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// Redirect the user to Fitbit authorization
async function authorizeWithFitbit() {
    const codeVerifier = generateCodeVerifier();
    localStorage.setItem("code_verifier", codeVerifier); // Save the verifier for later

    const codeChallenge = await generateCodeChallenge(codeVerifier);
    const scope = [
        "activity",
        "heartrate",
        "location",
        "nutrition",
        "profile",
        "settings",
        "sleep",
        "social",
        "weight",
    ].join(" ");

    const authUrl = `https://www.fitbit.com/oauth2/authorize?client_id=${CLIENT_ID}&response_type=code&code_challenge=${codeChallenge}&code_challenge_method=S256&scope=${encodeURIComponent(scope)}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`;
    window.location.href = authUrl; // Redirect to Fitbit authorization page
}

// Handle authorization response and exchange code for tokens
async function handleAuthorizationResponse() {
    const params = new URLSearchParams(window.location.search);
    const authorizationCode = params.get("code");

    if (!authorizationCode) {
        document.getElementById("status").innerText = "Authorization code not found.";
        return;
    }

    const codeVerifier = localStorage.getItem("code_verifier");
    if (!codeVerifier) {
        document.getElementById("status").innerText = "Code verifier not found.";
        return;
    }

    // Exchange authorization code for an access token
    const tokenResponse = await fetch("https://api.fitbit.com/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            client_id: CLIENT_ID,
            grant_type: "authorization_code",
            code: authorizationCode,
            code_verifier: codeVerifier,
            redirect_uri: REDIRECT_URI,
        }),
    });

    const tokenData = await tokenResponse.json();
    if (tokenData.access_token) {
        localStorage.setItem("access_token", tokenData.access_token);
        fetchHeartRateData(tokenData.access_token);
    } else {
        document.getElementById("status").innerText = "Failed to retrieve access token.";
    }
}

// Fetch heart rate data and store it in a global variable
async function fetchHeartRateData(accessToken) {
    const fitbitUrl = "https://api.fitbit.com/1/user/-/activities/heart/date/today/1d.json";

    const response = await fetch(fitbitUrl, {
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
    });

    const data = await response.json();

    // Save the Fitbit data to localStorage
    localStorage.setItem("fitbit_data", JSON.stringify(data));

    document.getElementById("status").innerText = "Fitbit data saved to localStorage.";
    console.log(data);
    
}
