from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


# Create the base class for declarative models
Base = declarative_base()

# Define the Fingerprint model
class Fingerprint(Base):
    __tablename__ = 'fingerprints'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(String(255), nullable=False, unique=True)
    
    def __repr__(self):
        return f"<Fingerprint(id={self.id}, fingerprint='{self.fingerprint}')>"

# Database setup function
def setup_database(db_url='sqlite:///fingerprints.db'):
  
    # Create engine
    engine = create_engine(db_url, echo=True)  # echo=True for SQL logging
    
    # Create all tables
    Base.metadata.create_all(engine)
    
    # Create session factory
    Session = sessionmaker(bind=engine)
    
    return engine, Session


def add_fingerprint(session, fingerprint_value):
    """Add a new fingerprint to the database"""
    try:
        new_fp = Fingerprint(fingerprint=fingerprint_value)
        session.add(new_fp)
        session.commit()
        return new_fp
    except Exception as e:
        session.rollback()
        raise e

def get_fingerprint_by_id(session, fp_id):
    """Get fingerprint by ID"""
    return session.query(Fingerprint).filter_by(id=fp_id).first()

def get_fingerprint_by_value(session, fingerprint_value):
    """Get fingerprint by value"""
    return session.query(Fingerprint).filter_by(fingerprint=fingerprint_value).first()

def delete_fingerprint(session, fp_id):
    """Delete fingerprint by ID"""
    fp = session.query(Fingerprint).filter_by(id=fp_id).first()
    if fp:
        session.delete(fp)
        session.commit()
        return True
    return False

def get_all_fingerprints(session):
    """Get all fingerprints"""
    return session.query(Fingerprint).all()

