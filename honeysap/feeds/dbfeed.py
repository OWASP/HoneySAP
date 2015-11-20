# ===========
# HoneySAP - SAP low-interaction honeypot
#
# Copyright (C) 2015 by Martin Gallo, Core Security
#
# The library was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# ==============

# Standard imports

# External imports
from sqlalchemy import create_engine
from sqlalchemy.schema import Column
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.types import Integer, DateTime, String, Text
# Custom imports
from honeysap.core.feed import BaseFeed


Base = declarative_base()


class DBEvent(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    session = Column(String(64))
    timestamp = Column(DateTime)
    event = Column(Text)


class DBFeed(BaseFeed):
    """ Database based feed class
    """

    @property
    def db_engine(self):
        return self.config.get("db_engine")

    @property
    def db_echo(self):
        return self.config.get("db_echo", False)

    def setup(self):
        """Initializes the database connection"""
        self.engine = create_engine(self.db_engine,
                                    echo=self.db_echo)
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        self.logger.debug("Database connection created with '%s'", self.db_engine)

    def stop(self):
        """Stops the database connection"""
        self.session.close_all()
        self.logger.debug("Closed database session")

    def log(self, event):
        """Logs an event in the database"""
        dbevent = DBEvent(session=str(event.session.uuid),
                          timestamp=event.timestamp,
                          event=repr(event))
        self.session.add(dbevent)
        self.session.commit()

    def consume(self, queue):
        pass
