



```


███████╗    ██████╗  █████╗ ██╗   ██╗███████╗     ██████╗ ███████╗    ██████╗ ███████╗██████╗ 
╚════██║    ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝    ██╔═══██╗██╔════╝    ██╔══██╗██╔════╝██╔══██╗
    ██╔╝    ██║  ██║███████║ ╚████╔╝ ███████╗    ██║   ██║█████╗      ██████╔╝█████╗  ██║  ██║
   ██╔╝     ██║  ██║██╔══██║  ╚██╔╝  ╚════██║    ██║   ██║██╔══╝      ██╔══██╗██╔══╝  ██║  ██║
   ██║      ██████╔╝██║  ██║   ██║   ███████║    ╚██████╔╝██║         ██║  ██║███████╗██████╔╝
   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝     ╚═════╝ ╚═╝         ╚═╝  ╚═╝╚══════╝╚═════╝ 
                                                                                              
██████╗  █████╗ ██╗   ██╗    ███████╗                                                         
██╔══██╗██╔══██╗╚██╗ ██╔╝    ╚════██║                                                         
██║  ██║███████║ ╚████╔╝         ██╔╝                                                         
██║  ██║██╔══██║  ╚██╔╝         ██╔╝                                                          
██████╔╝██║  ██║   ██║          ██║                                                           
╚═════╝ ╚═╝  ╚═╝   ╚═╝          ╚═╝                                                           
                                                                                              


```





## Active Directory Enumeration with LDAP queries 

### Day 7

For the last day of 7daysofRed, we're going to be covering LDAP queries.These are used in almost every Active Directory enumeration tool, such as PowerView and BloodHound. In an Active Directory environment there are several protocols that are used in order to transmit data ,two of the major ones being  Kerberos and LDAP. Since we are addressing LDAP in this post, Kerberos is out of scope for now. LDAP stands for Lightweight Directory Access Protocol, and its server is usually hosted on a domain controller. A domain controller is where all your data for every domain user ,group and host lives in the form of objects,and ntds.dit being the Active Directory Database file is also stored in the domain controller. LDAP is usually used to query these objects from the domain controller through the use of LDAP queries. In most cases once you have access to any authenicated user on a network, you can query the domain controller through LDAP. Having a look at LDAP user search request in wireshark may shed some light on what's going on when you send a query out to a domain controller. 

![image](https://user-images.githubusercontent.com/55005881/113821379-06a85000-974a-11eb-975f-d4eb4383b8ef.png)



In this capture you can see the search base or domain where the query is to be constrained to, "dc=ragee,dc=local". You can also see that the scope requested was the wholeSubtree,which indicates that the search base and all entries under it will be included in the search results.The next revelant field would be the filter, which constrains the search results even further and only specifies a certain user. The filter here is `(&(samAccountName=user001)(objectClass=*)`, and its filtering the inital results for user001 and returning all the user attributes associated with that user.The attributes requested are listed under that in the attributes section.This is the response to this query:

![image](https://user-images.githubusercontent.com/55005881/113821405-0dcf5e00-974a-11eb-8dd8-631ef59c1454.png)




As you can see the information was returned for each user attribute requested for the user user001.

*Code: Performs a basic LDAP query with a domain user account name as an argument.*

```c#
using System;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;



namespace GetDomainUsers
{
    class Program
    {
       
        static void Main(string[] args)
        {
            string user = args[0];
            try
            {
                Domain domain = Domain.GetCurrentDomain();
                

                //Create Ldap connection object
                DirectoryEntry ldapconn = new DirectoryEntry("LDAP://"+domain.Name);
                
                //Create ldap searcher
                DirectorySearcher searcher = new DirectorySearcher(ldapconn);
                //Attach ldapquery filter
                searcher.Filter="(&(objectClass=user)(sAMAccountName="+user+")";
                //Gets Result
                SearchResult result = searcher.FindOne();
                if (result != null)
                {
                    ResultPropertyCollection fields = result.Properties;
                    foreach(String ldapField in fields.PropertyNames)
                    {
                        foreach(Object myCollection in fields[ldapField])
                        {
                            Console.WriteLine(String.Format("{0,-20} : {1}",
                                ldapField, myCollection.ToString()));
                        }
                    }
                }
                else
                {
                    Console.WriteLine("User Doesn't Exist");
                }

                

                //

            }
            catch (Exception e)
            {
                Console.WriteLine("Problem Connecting {0}", e.Message.ToString());
            }
            


            

            
        }
    }
}

```

Thanks for reading the 7daysofRed series, hopefully you learned something new or refreshed on some old details.More educational and research blog posts coming soon, so stay tuned.
