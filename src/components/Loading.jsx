function Loading() {
    return (
        <div className="w-full h-[50%] flex justify-center items-center">
            <svg className="animate-spin h-20 w-auto" viewBox="25 25 50 50">
                <circle className="fill-transparent stroke-[4] [stroke-dasharray:80] stroke-white" cx="50" cy="50" r="20" strokeLinecap="round"/>
            </svg>
        </div>
    );
}

export default Loading;