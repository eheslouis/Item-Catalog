from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///catalogItem.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

user1 = User(name="Elodie", email="e@e.e")
session.add(user1)
session.commit()

category1 = Category(name="Soccer")
session.add(category1)
session.commit()

item1 = Item(name="Jersey", description="This is a jersey",
             category=category1, user_id=user1.id)
session.add(item1)
session.commit()

item2 = Item(name="Ball", description="This is a ball",
             category=category1, user_id=user1.id)
session.add(item2)
session.commit()

category2 = Category(name="Basketball")
session.add(category2)
session.commit()

item2 = Item(name="Ball", description="this is a ball",
             category=category2, user_id=user1.id)
session.add(item2)
session.commit()

category3 = Category(name="Baseball")
session.add(category3)
session.commit()

item3 = Item(name="Bat", description="This is a bat",
             category=category3, user_id=user1.id)
session.add(item3)
session.commit()

category4 = Category(name="Frisbee")
session.add(category4)
session.commit()
