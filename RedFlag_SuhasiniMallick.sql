-- =====================================================
-- RedFlag - Fraud Detection Submission
-- Student: Suhasini Mallick
-- =====================================================

USE redflag;

-- =====================================================
-- PATTERN 1 - VELOCITY FRAUD
-- Find users who perform 30 or more transactions in a single day.
-- =====================================================

SELECT
    user_id,
    DATE(txn_time) AS attack_date,
    COUNT(*) AS daily_transactions
FROM transactions
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY daily_transactions DESC; 
-- Findings:
-- Total suspect user-days flagged: 50
-- Top suspects:
-- User 14561 -> 35 transactions on 2024-04-02
-- User 14522 -> 35 transactions on 2024-05-27
-- User 14568 -> 34 transactions on 2024-01-23


-- =====================================================
-- PATTERN 2 - ROUND AMOUNT CLUSTERING
-- Find users who repeatedly make transactions using round amounts.
-- =====================================================

SELECT
    user_id,
    COUNT(*) AS round_transactions
FROM transactions
WHERE amount IN (100, 200, 500, 1000, 2000, 5000, 10000)
GROUP BY user_id
HAVING COUNT(*) >= 15
ORDER BY round_transactions DESC;


-- Findings:
-- Total suspect users found: 25
-- Top suspects:
-- User 14533 -> 30 round amount transactions
-- User 14534 -> 30 round amount transactions
-- User 14535 -> 30 round amount transactions 


-- =====================================================
-- PATTERN 3 - CARD TESTING
-- Find users who make 30 or more transactions below Rs.10 in one day.
-- =====================================================

SELECT
    user_id,
    DATE(txn_time) AS txn_date,
    COUNT(*) AS small_transactions
FROM transactions
WHERE amount < 10
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY small_transactions DESC; 

-- Findings:
-- Total suspect user-days flagged: 20
-- Top suspects:
-- User 14569 -> 60 transactions on 2024-04-03
-- User 14556 -> 60 transactions on 2024-05-28
-- User 14564 -> 59 transactions on 2024-02-15 


-- =====================================================
-- PATTERN 4 - FAILED THEN SUCCEEDED (SIMPLIFIED)
-- Find users having 20 or more failed transactions.
-- =====================================================

SELECT
    user_id,
    COUNT(*) AS failed_transactions
FROM transactions
WHERE status = 'FAILED'
GROUP BY user_id
HAVING COUNT(*) >= 20
ORDER BY failed_transactions DESC;   

-- Findings:
-- Total suspect users found: 25
-- My observation:
-- User 14595 -> 35 failed transactions
-- User 14593 -> 34 failed transactions
-- User 14576 -> 33 failed transactions


-- =====================================================
-- PATTERN 5 - ODD HOUR CONCENTRATION
-- Find users whose 80% or more transactions happen between 2 AM and 4 AM.
-- =====================================================

SELECT
    user_id,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1
            ELSE 0
        END
    ) AS odd_hour_transactions
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 30
AND
SUM(
    CASE
        WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1
        ELSE 0
    END
) / COUNT(*) >= 0.80
ORDER BY odd_hour_transactions DESC; 


-- Findings:
-- Total suspect users found: 20
-- Top suspects:
-- User 14608 -> 58 odd-hour transactions out of 63 total
-- User 14606 -> 49 odd-hour transactions out of 52 total
-- User 14607 -> 46 odd-hour transactions out of 53 total

-- =====================================================
-- PATTERN 6 - MULE ACCOUNTS
-- In this pattern, I looked for users who received many CREDIT
-- transactions. Users with a high number of credits may be
-- suspicious and could be used as mule accounts.
-- ===================================================== 
SELECT
    user_id,
    COUNT(*) AS credit_transactions
FROM transactions
WHERE txn_type = 'CREDIT'
GROUP BY user_id
HAVING COUNT(*) >= 8
ORDER BY credit_transactions DESC;

-- My Findings:
-- I found 15 suspicious users.
-- These users received many CREDIT transactions.
-- They may be used as mule accounts.

-- =====================================================
-- PATTERN 7 - REFUND ABUSE
-- In this pattern, I checked users who have a very high
-- refund ratio. If refund transactions are more than 40%
-- of all transactions, the account may be suspicious.
-- =====================================================
SELECT
    user_id,
    COUNT(*) AS total_transactions,
    SUM(CASE
            WHEN txn_type = 'REFUND' THEN 1
            ELSE 0
        END) AS refund_transactions
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 20
AND
SUM(CASE
        WHEN txn_type = 'REFUND' THEN 1
        ELSE 0
    END) / COUNT(*) > 0.40
ORDER BY refund_transactions DESC;


-- My Findings:
-- I found 25 suspicious users.
-- These users have a very high refund ratio.
-- Their accounts need further investigation.

-- ============================================================
-- PATTERN 8 - MERCHANT COLLUSION
-- In this pattern, I checked merchants where a few users
-- contribute most of the transaction value.
-- Such merchants may be involved in money laundering.
-- ============================================================

WITH merchant_user AS (
SELECT merchant_id,
       user_id,
       SUM(amount) AS user_volume
FROM transactions
GROUP BY merchant_id,user_id
),

ranked_users AS (
SELECT *,
ROW_NUMBER() OVER(
PARTITION BY merchant_id
ORDER BY user_volume DESC) rn
FROM merchant_user
),

top5 AS (
SELECT merchant_id,
SUM(user_volume) AS top5_volume
FROM ranked_users
WHERE rn<=5
GROUP BY merchant_id
),

merchant_total AS (
SELECT merchant_id,
SUM(amount) total_volume
FROM transactions
GROUP BY merchant_id
)

SELECT
t.merchant_id,
t.top5_volume,
m.total_volume,
ROUND((t.top5_volume*100)/m.total_volume,2) percentage
FROM top5 t
JOIN merchant_total m
ON t.merchant_id=m.merchant_id
WHERE (t.top5_volume/m.total_volume)>0.60;

-- My Findings:
-- I found 15 suspicious merchants.
-- A few users generated most of their transaction amount.
-- These merchants may be involved in suspicious activities.


-- =====================================================
-- PATTERN 9 - JUST UNDER THRESHOLD
-- Here I looked for users who repeatedly made
-- transactions of exactly Rs.9999.
-- This can be a sign of structuring to avoid checks.
-- =====================================================
SELECT
    user_id,
    COUNT(*) AS threshold_transactions
FROM transactions
WHERE amount = 9999
GROUP BY user_id
HAVING COUNT(*) >= 10
ORDER BY threshold_transactions DESC;

-- My Findings:
-- I found 20 suspicious users.
-- These users made many transactions of ₹9,999.
-- This may be an attempt to avoid transaction reporting thresholds.

-- ============================================================
-- PATTERN 10 - DORMANT THEN ACTIVE
-- In this pattern, I checked users who remained inactive
-- for 90 or more days and then suddenly became active.
-- ============================================================

WITH txn_gap AS (
SELECT
user_id,
txn_time,
LAG(txn_time) OVER(
PARTITION BY user_id
ORDER BY txn_time) previous_txn
FROM transactions
)
SELECT
user_id,
COUNT(*) suspicious_transactions
FROM txn_gap
WHERE TIMESTAMPDIFF(DAY,previous_txn,txn_time)>=90
GROUP BY user_id
ORDER BY suspicious_transactions DESC;

-- My Findings:
-- I found 26 suspicious users.
-- These accounts were inactive for a long time.
-- They suddenly became active, which looks suspicious.

-- ============================================================
-- PATTERN 11 - VELOCITY SPIKE
-- In this pattern, I checked users whose monthly transaction
-- count suddenly increased to at least 5 times their average
-- monthly transactions. Such users may be victims of account takeover.
-- ============================================================

WITH monthly_txn AS (
SELECT
    user_id,
    DATE_FORMAT(txn_time,'%Y-%m') AS month,
    COUNT(*) AS monthly_count
FROM transactions
GROUP BY user_id, DATE_FORMAT(txn_time,'%Y-%m')
),

user_stats AS (
SELECT
    user_id,
    AVG(monthly_count) AS avg_txn,
    MAX(monthly_count) AS peak_txn
FROM monthly_txn
GROUP BY user_id
)

SELECT
    user_id,
    ROUND(avg_txn,2) AS average_transactions,
    peak_txn AS peak_transactions,
    ROUND(peak_txn/avg_txn,2) AS spike_ratio
FROM user_stats
WHERE peak_txn >= 20
AND peak_txn >= avg_txn * 5
ORDER BY spike_ratio DESC;

-- My Findings:
-- I found 40 suspicious users.
-- Their monthly transactions increased suddenly.
-- This may indicate account takeover.

-- ============================================================
-- PATTERN 12 - GEOGRAPHIC IMPOSSIBILITY
-- In this pattern, I checked users who made two consecutive
-- transactions from different cities within 60 minutes.
-- Such activity may indicate account takeover or stolen cards.
-- ============================================================

WITH city_change AS (
SELECT
    user_id,
    city,
    txn_time,
    LAG(city) OVER(
        PARTITION BY user_id
        ORDER BY txn_time
    ) AS previous_city,
    LAG(txn_time) OVER(
        PARTITION BY user_id
        ORDER BY txn_time
    ) AS previous_time
FROM transactions
)

SELECT
    user_id,
    previous_city,
    city AS current_city,
    previous_time,
    txn_time,
    TIMESTAMPDIFF(MINUTE, previous_time, txn_time) AS minutes_gap
FROM city_change
WHERE previous_city IS NOT NULL
AND previous_city <> city
AND TIMESTAMPDIFF(MINUTE, previous_time, txn_time) <= 60
ORDER BY user_id, txn_time;

-- My Findings:
-- I found 15 suspicious users.
-- These users made transactions from different cities within a short time.
-- This activity may indicate account takeover, card sharing.


