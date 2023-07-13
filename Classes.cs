using System;
using System.Text;
using Newtonsoft.Json;
class Message
{
    public string MessageID {get; set;}
    public string UserID {get; set;}
    public string UserName {get; set;}
    public string TimeSent {get; set;}
    public string MessageText {get; set;}
}
class Guild
{
    public string Name {get; set;}
    public string ID {get; set;}
    public string OwnerID {get; set;}
    public string Description {get; set;}
    public List<Channel> Channels {get; set;}
}
class Channel
{
    public string Name {get; set;}
    public string ID {get; set;}
    public int Type {get; set;}
    public string Description {get; set;}
    public int IsDM {get; set;}
}
