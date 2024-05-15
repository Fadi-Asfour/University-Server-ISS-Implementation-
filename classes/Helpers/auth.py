# This created to help in getting user data
import sqlite3
from classes.Server.Models.User import User


class auth:
    con = sqlite3.connect('userdata.db', check_same_thread=False)
    cur = con.cursor()

    def getID(self, publicKey):  # get user id by public key
        id = self.cur.execute(
            "SELECT id FROM `userdata` WHERE public_key = ? ORDER BY id", (publicKey,)).fetchone()
        if not id:
            return None
        id = id[0]
        return id

    def getUserByID(self, id):
        userRow = self.cur.execute(
            "SELECT * FROM `userdata` WHERE id = " + str(id) + " ORDER BY id").fetchone()
        if not userRow:
            return None
        userObject = User(userRow[0], userRow[1], userRow[2],
                          userRow[3], userRow[4], userRow[5], userRow[6],
                          userRow[7], userRow[8], userRow[9])
        return userObject

    def getUserByPK(self, publicKey):
        userRow = self.cur.execute(
            "SELECT * FROM `userdata` WHERE public_key = ? ORDER BY id", (publicKey,)).fetchone()
        if not userRow:
            return None
        userObject = User(userRow[0], userRow[1], userRow[2],
                          userRow[3], userRow[4], userRow[5], userRow[6],
                          userRow[7], userRow[8], userRow[9])
        return userObject
