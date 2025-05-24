




// extension
document.getElementById('clickMe').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: extractMessageIds
  });
});

async function extractMessageIds() {
  
  async function verifyEmail(prompt, apiKey) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
  
  
    const requestBody = {
    contents: [{
        parts: [{
            text: `Analyze '${prompt}' for email spoofing, focusing on common tricks like number substitutions (e.g. '1' for 'i', '0' for 'o') and misspellings of known domains/companies. Return a raw JSON object with format {"rating": <0-1 score>, "reason": "<10 word explanation>"} where 1=likely spoofed, 0=100% safe. For any detected risk, use a rating of at least 0.5. Do not use markdown, quotes, or any formatting - return only the JSON.`
        }]
    }]};
      
    
    const response = await fetch(url, {
        method: 'POST',
        headers: {
        'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
    });
    
    if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(`API request failed with status ${response.status}: ${errorBody}`);
    }
    
    const result = await response.json();
    if (result.candidates && result.candidates[0] && result.candidates[0].content) {
        const resp = JSON.parse(result.candidates[0].content.parts[0].text);
        const { rating, reason } = resp;
        return { rating, reason };
        
    }
  }
    
  
  function extractEmails(text) {
    const htmlDecoded = text.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
  
    const emailRegex = /(?:[a-zA-Z0-9._%+-]+)@(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
    const matches = htmlDecoded.match(emailRegex) || [];
  
    // Optional: Deduplicate and normalize
    return [...new Set(matches.map(email => email.trim().toLowerCase()))];
  }
  
  
  
  async function refreshAccessToken(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN) {
      
      const tokenUrl = 'https://oauth2.googleapis.com/token';
  
      const res = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          refresh_token: REFRESH_TOKEN,
          grant_type: 'refresh_token'
      })
      });
  
      const data = await res.json();
  
      if (res.ok) {
          return data.access_token;
      } else {
          console.error('❌ Error refreshing token:', data);
      }
  }
  
  async function listMessages(ACCESS_TOKEN) {
    const res = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages', {
      headers: {
        Authorization: `Bearer ${ACCESS_TOKEN}`
      }
    });
  
    const data = await res.json();
    if (!data) {
      const ACCESS_TOKEN = refreshAccessToken();
      listMessages(ACCESS_TOKEN);
    } else {
      return data.messages;
    }
  }
  
  async function getMessageData(messageId, ACCESS_TOKEN) {
    const res = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}`, {
      headers: {
        Authorization: `Bearer ${ACCESS_TOKEN}`
      }
    });
  
    const data = await res.json();
    if (!data) {
      const ACCESS_TOKEN = refreshAccessToken();
      getMessageData(messageId, ACCESS_TOKEN);
    } else {
      return data;
    }
  }
  
  
  const GMAIL_CLIENT_ID = "<your key>";
const GMAIL_CLIENT_SECRET = "<your key>";
  const GMAIL_REFRESH_TOKEN = "<your key>";
  const GEMINI_API_KEY = "<your key>";
  
  const ACCESS_TOKEN = await refreshAccessToken(GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REFRESH_TOKEN);
  console.log(ACCESS_TOKEN)

  const messageDivs = document.querySelectorAll('div.adn.ads');
  const messageIds = [];

  if (messageDivs.length > 0) {
    messageDivs.forEach(async(div, index) => {
      const legacyId = div.getAttribute('data-legacy-message-id');
      if (legacyId) {
        messageIds.push(legacyId);
        console.log(`📨 Message ${index + 1} ID: ${legacyId}`);
        const messageData = await getMessageData(messageIds[0], ACCESS_TOKEN).catch(console.error);
        const vul_texts = [];
        const vul_results = {};

        messageData.payload.parts.forEach(part => {
          if (part.body.size > 0) {
            const text = part.body.data;
            const decodedText = decodeURIComponent(escape(atob(text.replace(/-/g, '+').replace(/_/g, '/'))));
            vul_texts.push({"location": "body", "text": decodedText});
          }
        });

        const vul_locations = ["From", "Cc", "Subject"];
        for (const location of vul_locations) {
          try {
            const vuln_text = messageData.payload.headers.find(header => header.name === location).value;
            vul_texts.push({"location": location, "text": vuln_text});
          } catch (error) {
            console.log("Skipping header: "+location);
          }
        }

        for (const vul_text of vul_texts) {
          const emails = extractEmails(vul_text.text);
          for (const email of emails) {
            const result = await verifyEmail(email, GEMINI_API_KEY);
            let threat = false;
            if (result.rating >= 0.5) {
              threat = true;
            } 
            if (Object.prototype.hasOwnProperty.call(vul_results, email)) {
              vul_results[email].location.push(vul_text.location);
            } else {
              vul_results[email] = {"location": [vul_text.location], "rating": result.rating, "reason": result.reason, "threat": threat};
            }
          }
        } 

        for (const [email, result] of Object.entries(vul_results)) {
          console.log(email,result);
          if (result.rating>0.5){
            alert(`The email '${email}' is likely a threat.\nReason: ${result.reason}\nThreat pobability: ${result.rating} `)
          }
          else{
            alert(`The email '${email}' is likely safe.\nReason: ${result.reason}\nThreat pobability: ${result.rating} `)
        }
          
        }
      }
    });
  } else {
    alert("❌ No message divs found with class 'adn ads'.");
  }

  if (messageIds.length > 0) {
    console.log(`✅ Found ${messageIds.length} message ID(s):\n${messageIds.join(', ')}`);
  } else {
    console.log("⚠️ Script ran, but no message IDs were found.");
  }
}

