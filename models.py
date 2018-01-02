from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context

Base = declarative_base()

# Connect to Database and create database session
##   USE THIS FOR REFERENCE:
##   FSND/CRUD/full-stack-foundations/Lesson-4/Final-Project/


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(64))
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    @property
    def serialize(self):
        # return object data in easily serializable form
        return {
        'id': self.id,
        'username': self.username,
        'email': self.email
        }


class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    ownerEmail = Column(String(250), ForeignKey('user.email'))
    owner = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
        'id': self.id,
        'name': self.name,
        'ownerEmail': self.ownerEmail
        }


class Item(Base):
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    picture = Column(String)
    description = Column(String(500))
    addDate = Column(DateTime())
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    ownerEmail = Column(String(250), ForeignKey('user.email'))
    #owner_id = Column(Integer, ForeignKey('user.id'))
    owner = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
        'id': self.id,
        'name': self.name,
        'picture': self.picture,
        'description': self.description,
        'addDate': self.addDate,
        'category_id': self.category_id,
        'ownerEmail': self.ownerEmail,
        'owner_id': self.owner_id
            }


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)

