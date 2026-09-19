ZehnMS prototype
================

What it is
----------
A static showcase of the ZehnMS shop app (point of sale, stock and accounts).
It shows how the screens look, filled with made-up data for a fictional shop,
"Al-Noor General Store", Lahore. It is NOT the working app:

  * nothing is saved and nothing is sent anywhere,
  * forms and most buttons do nothing,
  * a few buttons walk to the next screen:
    Sign in -> Dashboard -> New sale (Till) -> Take cash (Receipt).

It is separate from the real application (the Django project in the folder
above). Changing these files does not change the app, and the app does not
use them.

How to open it
--------------
Double-click index.html. It opens in any modern browser straight from the
disk (file://). No server, no internet, no install, no build step.
Every page also opens on its own by double-clicking it.

Pages
-----
  index.html            Start page: every screen with a one-line description
  login.html            Sign in
  setup.html            First-run setup, 2 steps: owner account, shop details
  dashboard.html        Summary figures, Today statement, 7-day sales chart,
                        needs attention, low stock
  till.html             The till: scan bar, bill (incl. weighed "Atta 0.5 kg"
                        and variant "Bread - Large"), big total, Cash/Bank/
                        Credit, tendered and change, F-key chips.
                        "Show size picker" opens the Bread size picker;
                        till.html#picker opens with it already showing.
  receipt.html          Thermal receipt on screen with Print / New sale
  products.html         Product list, filters, Low/Out pills, grouped Bread
                        family (click the row to fold/unfold the 3 sizes)
  product-form.html     Add product: Basics, Pricing (amount on cost:
                        100 + 20 = 120) with live summary, Stock; the
                        Add category side panel is open beside the form
  purchase.html         Supplier bill with lines and totals
  customers.html        Parties with balances: owes you / you owe / settled
  customer-ledger.html  One customer's ledger, running balance, and the
                        Receive payment side panel
  reports.html          Reports home grouped Sales / Stock / Money / Team
  trial-balance.html    Trial balance (debits = credits)
  settings.html         Settings sections, feature switches (some "Not in
                        your edition"), Licence panel (Trial: 7 days left,
                        paste-key field)

Little interactions (vanilla JS, assets/prototype.js)
-----------------------------------------------------
Info (i) tooltips open on click, the Cash/Bank/Credit switch changes the pay
button label, feature switches flip, side panels close and reopen, the phone
menu drawer opens. Nothing is stored.

Dummy data
----------
All names, phone numbers (0300-000000x pattern), invoices (INV-00123 style)
and amounts are invented. Totals add up. No real people's data.

Files
-----
  assets/zehnms-prototype.css   One stylesheet built from the real design
                                tokens, shell and component styles
  assets/prototype.js           The small interactions above
  assets/fonts/                 Public Sans (variable woff2) and its SIL Open
                                Font License (OFL-PublicSans.txt)
  assets/icons/                 Bootstrap Icons 1.11.3 (MIT licence, see the
                                header of bootstrap-icons.min.css)
