"""Using rauth library maintained by Max Countryman"""
from rauth import OAuth1Session

"""set application keys issued by TradeKing website when a new developer 
application is created; personal keys are not hard coded here for
security reasons"""
cKey = 'consumer.Key'
cSecret = 'consumer.Secret'
oKey = 'oauth.Key'
oSecret = 'oauth.Secret'

"""Use the keys to instantiate a session"""
tradeking = OAuth1Session(consumer_key = cKey,
						consumer_secret = cSecret,
						access_token = oKey,
						access_token_secret = oSecret)

"""Set the get request parameters"""						
params = {'symbols': 'aapl,nflx,fb', 'fids': 'last,pvol,pcls'}

"""Fetch data market quotes data"""
r = tradeking.get('https://api.tradeking.com/v1/market/ext/quotes.json', 
					params = params)

"""Parse JSON object"""
json_obj = r.json()
print("\nStock: Last Price, Exchange, Previous Day Volume, Previous Day Close\n")

for dict_item in list((json_obj['response']['quotes']['quote'])):
	symb = dict_item['symbol']
	last_price = dict_item['last']
	exchange = dict_item['exch']
	prev_day_vol = dict_item['pvol']
	prev_day_close = dict_item['pcls']
	print (u'{0}: {1} {2} {3} {4}'.format(symb, last_price, exchange, 
										  prev_day_vol, prev_day_close))
	