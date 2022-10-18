import Loading from "./Loading";

function Home() {
    return ( 
        <div className="w-full h-full flex flex-col items-center">
            <span className="text-6xl text-center font-semibold mt-24 animate-fadein">
                Cryptile
                <p className="text-lg pt-2 font-normal"> Encrypt and Decrypt your files securely </p>
            </span>
            <Loading />
        </div>
     );
}

export default Home;