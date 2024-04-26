import * as mongodb from "mongodb";
import { Location } from "./location";
export interface Client {

    clientname: string;
    location: Location[];
    userRefs: mongodb.ObjectId[]; // Array of references to User objects
    _id?: mongodb.ObjectId;
    
}