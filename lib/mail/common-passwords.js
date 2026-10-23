"use strict";
/* Frozen list of common passwords (lowercase), for password-policy.js.

   The policy already requires 12+ characters, so the short classics ("123456") can never
   pass anyway; they are kept because the check lowercases and also strips a trailing run
   of digits and symbols, which turns "Password123456!" back into "password". The rest are
   the long entries that dominate public breach lists, plus company-flavoured guesses. */

module.exports = Object.freeze([
  "123456", "123456789", "12345678", "1234567890", "12345", "1234567", "password", "qwerty", "qwertyuiop",
  "111111", "123123", "abc123", "000000", "iloveyou", "1q2w3e4r", "1q2w3e4r5t", "1q2w3e4r5t6y", "qwerty123",
  "admin", "welcome", "monkey", "dragon", "letmein", "football", "baseball", "sunshine", "princess", "master",
  "shadow", "superman", "michael", "jennifer", "trustno1", "starwars", "whatever", "freedom", "passw0rd",
  "p@ssw0rd", "p@ssword", "zaq12wsx", "zaq1zaq1", "1qaz2wsx", "1qaz2wsx3edc", "qazwsx", "qazwsxedc",
  "asdfghjkl", "asdfghjkl123", "zxcvbnm", "zxcvbnm123", "qwertyuiop123", "qwertyuiop12", "qwerty123456",
  "qwerty12345", "password1", "password12", "password123", "password1234", "password12345", "password123456",
  "passwordpassword", "mypassword", "mypassword123", "newpassword", "changeme", "changeme123", "changemenow",
  "iloveyou123", "iloveyou1234", "iloveyouiloveyou", "welcome123", "welcome1234", "welcometothejungle",
  "letmein123", "letmeinnow", "administrator", "administrator1", "admin123456", "adminadmin", "admin12345678",
  "rootroot", "toor", "secret", "secret123", "supersecret", "topsecret", "default", "default123",
  "123456789012", "1234567890123", "12345678910", "123456789a", "123456789abc", "123123123123",
  "111111111111", "000000000000", "112233445566", "987654321", "9876543210", "0987654321",
  "abcdefghijkl", "abcdefgh1234", "abcd12345678", "abc123456789", "aaaaaaaaaaaa", "qqqqqqqqqqqq",
  "football123", "baseball123", "basketball", "basketball123", "soccer1234", "cricket", "cricket123",
  "pakistan", "pakistan123", "pakistan1947", "pakistanzindabad", "islamabad", "karachi", "karachi123",
  "lahore", "lahore123", "lahore12345", "rawalpindi", "birmingham", "birmingham123", "london123",
  "strategic", "strategic123", "zehnox", "zehnox123", "chess", "chessmaster", "checkmate",
  "checkmate123", "grandmaster", "queensgambit", "trading", "trader123", "forex", "forextrader",
  "investment", "investor123", "money123456", "moneymoney", "bitcoin", "bitcoin123", "crypto123",
  "summer2024", "summer2025", "summer2026", "winter2024", "winter2025", "winter2026", "spring2026",
  "autumn2026", "january2026", "september2026", "welcome2024", "welcome2025", "welcome2026",
  "password2024", "password2025", "password2026", "passw0rd123", "p@ssw0rd123", "p@ssw0rd1234",
  "correcthorsebatterystaple", "correct horse battery staple", "thequickbrownfox", "iloveyoumore",
  "loveyouforever", "sweetheart", "butterfly", "chocolate", "blink182", "pokemon", "minecraft",
  "fortnite", "computer", "internet", "samsung", "google", "googlegoogle", "facebook", "instagram",
  "whatsapp", "microsoft", "windows10", "windows11", "linux", "ubuntu", "hello123", "helloworld",
  "helloworld123", "hellohello", "goodluck", "goodmorning", "nopassword", "nothing", "blahblah",
  "testtest", "test12345678", "testing123", "testpassword", "temp12345678", "temporary", "guest12345",
  "user12345678", "useruser", "email123", "mail12345678", "postmaster", "webmaster", "mailbox",
  "mailbox123", "contact123", "info12345678", "office123456", "company123", "business123",
]);
