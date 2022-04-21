const axios = require('axios');

const response = await axios.post(
    'http://localhost:28139/api/oauth/token/',
    {
        'grant_type': 'client_credentials'
    },
    {
        auth: {
            username: 'foo',
            password: 'bar'
        }
    }
);
