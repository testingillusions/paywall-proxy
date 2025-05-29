testuser@example.com = 3603b3d381d05fc28ef60adfc11c17769c9ab6945e6798a8cf87f3db0b2b4422

Create

curl.exe -k -X POST -H "Content-Type: application/json" ^
-H "X-Admin-Secret: upgV6j6vTXRcPa868mJ6r9KiERJxtXi6GQTskg9NNM3vec7yH7h7J6QcyA5ieAoD" ^
-d "{\"userIdentifier\": \"testuser@example.com\", \"subscriptionStatus\": \"active\"}" ^
https://localhost/api/generate-token

Update

curl.exe -k -X POST -H "Content-Type: application/json" ^
-H "X-Admin-Secret: upgV6j6vTXRcPa868mJ6r9KiERJxtXi6GQTskg9NNM3vec7yH7h7J6QcyA5ieAoD" ^
-d "{\"userIdentifier\": \"testuser@example.com\", \"subscriptionStatus\": \"inactive\"}" ^
https://localhost/api/update-subscription-status


Test Login

curl.exe -k -H "Authorization: Bearer 3603b3d381d05fc28ef60adfc11c17769c9ab6945e6798a8cf87f3db0b2b4422" https://localhost/


curl -k "http://localhost/?apiKey=3603b3d381d05fc28ef60adfc11c17769c9ab6945e6798a8cf87f3db0b2b4422"

